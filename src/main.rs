extern crate clap;
extern crate curl;
extern crate rand;
#[macro_use]
extern crate serde_json;

use clap::{Arg, App, SubCommand};
use rand::{thread_rng, Rng};
use std::env;
use std::fmt;
use std::error::Error;
use std::io::{BufReader, Read};
use std::str;

use curl::easy::{Easy, List};

#[derive(Debug)]
struct OpenStackConfig {
  auth_url: String,
  project_domain: String,
  project_name: String,
  user_domain: String,
  username: String,
  password: String,
  region_name: String
}

#[derive(Debug)]
struct SwiftAuthInfo {
  token: String,
  url: String
}

#[derive(Debug)]
struct MissingToken;

impl fmt::Display for MissingToken {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Token not found in Keystone response headers")
  }
}

impl Error for MissingToken {
  fn description(&self) -> &str {
    "Token not found in Keystone response headers"
  }

  fn cause(&self) -> Option<&Error> {
    None
  }
}


#[derive(Debug)]
struct MissingSwiftUrl;

impl fmt::Display for MissingSwiftUrl {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Swift service endpoint URL not found in Keystone JSON catalog")
  }
}

impl Error for MissingSwiftUrl {
  fn description(&self) -> &str {
    "Swift service endpoint URL not found in Keystone JSON catalog"
  }

  fn cause(&self) -> Option<&Error> {
    None
  }
}


fn main() {
  let matches =
    App::new("backup2swift")
      .subcommand(SubCommand::with_name("setup")
        .about("setup container and create request signature")
        .arg(Arg::with_name("container")
            .takes_value(true)
            .required(true)
            .help("destination container name")))
      .get_matches();
  if let Some(matches) = matches.subcommand_matches("test") {
    let settings = get_os_settings();
    println!("{:?}", settings);
    let auth_info = get_token(settings).unwrap();
    let server_info =
      get_temp_url_key(&auth_info)
        .or_else(|e| set_temp_url_key(&auth_info, &create_random_key()))
        .unwrap();
    println!("{:?}", server_info);
  } else {
    println!("try 'backup2swift --help' for more information");
    ::std::process::exit(2)
  }
}

fn get_env(name: &str) -> String {
  env::var(name).expect(& format!("{} environment variable not defined", name))
}

fn get_os_settings() -> OpenStackConfig {
  let auth_url = get_env("OS_AUTH_URL");
  println!("OS_AUTH_URL: {}", &auth_url);
  let user_domain = get_env("OS_USER_DOMAIN_NAME");
  println!("OS_PROJECT_NAME: {}", &user_domain);
  let username = get_env("OS_USERNAME");
  println!("OS_USERNAME: {}", &username);
  let project_domain = get_env("OS_PROJECT_DOMAIN_NAME");
  println!("OS_PROJECT_NAME: {}", &project_domain);
  let project_name = get_env("OS_PROJECT_NAME");
  println!("OS_PROJECT_NAME: {}", &project_name);
  let password = get_env("OS_PASSWORD");
  println!("OS_PASSWORD: {}", &("*".repeat(password.len())));
  let region_name = get_env("OS_REGION_NAME");
  println!("OS_REGION_NAME: {}",  &region_name);

  OpenStackConfig {
    auth_url,
    user_domain,
    username,
    project_domain,
    project_name,
    password,
    region_name
  }
}

fn get_token(config: OpenStackConfig) -> Result<SwiftAuthInfo, Box<Error>> {
  let mut dst = Vec::new();
  let mut easy = Easy::new();
  let json = json!({
    "auth": {
      "identity": {
        "methods": [
          "password"
        ],
        "password": {
          "user": {
            "domain": {
              "name": config.user_domain
            },
            "name": config.username,
            "password": config.password
          }
        }
      },
      "scope": {
        "project": {
          "domain": {
            "name": config.project_domain
          },
          "name": config.project_name
        }
      }
    }
  });
  let json_bytes = serde_json::to_vec_pretty(&json).unwrap();
  let mut req_reader = BufReader::new(json_bytes.as_slice());
  let mut headers = List::new();
  let mut opt_token: Option<String> = None;
  headers.append("Content-Type: application/json");
  headers.append(format!("Content-Length: {}", json_bytes.len()).as_ref());
  headers.append("Accept: application/json");
  headers.append("Expect: ");
  easy.verbose(false);
  easy.post(true);
  easy.url(& format!("{}auth/tokens", config.auth_url))?;
  easy.http_headers(headers);
  {
    let mut transfer = easy.transfer();
    transfer.header_function(|header| {
      let mut splitter = str::from_utf8(header).unwrap().splitn(2, ": ");
      match splitter.next() {
        Some(name) if name.to_lowercase() == "x-subject-token" => {
          splitter.next().map(|s| s.to_owned()).map(|t| {
            opt_token = Some(t.trim().to_owned());
          }); ()
        }
        _ => ()
      }
      true
    })?;
    transfer.read_function(|into| {
      Ok(req_reader.read(into).unwrap())
    })?;
    transfer.write_function(|data| {
      dst.extend_from_slice(data);
      Ok(data.len())
    })?;
    transfer.perform()?
  }
  match opt_token {
    Some(token) => {
      let response_json: Result<serde_json::Value, serde_json::Error> =
        serde_json::from_slice(dst.as_slice());
      response_json
        .map(|j| {
          j.get("token")
            .and_then(|v| v.get("catalog"))
            .and_then(|v| v.as_array())
            .and_then(|catalog| get_swift_endpoint(catalog.iter(), config.region_name.to_owned()))
        })
        .map_err(|e| From::from(e))
        .and_then(|opt_url| {
          opt_url
            .map(|url| SwiftAuthInfo { token, url })
            .ok_or(MissingSwiftUrl)
            .map_err(|e| From::from(e))
        })

    },
    None => Err(From::from(MissingToken))
  }
}

fn get_swift_endpoint<'a,I>(
    catalog: I,
    region_name: String) -> Option<String> where I: Iterator<Item=&'a serde_json::Value> {
  catalog
    .filter_map(|item| {
      match item.get("type").and_then(|v| v.as_str()) {
        Some(t) if t == "object-store" =>
          item.get("endpoints").and_then(|v| v.as_array()).map(|v| v.into_iter()),
        _ => None
      }
    })
    .flat_map(|endpoints| endpoints)
    .find(|endpoint| {
      (match endpoint.get("interface").and_then(|v| v.as_str()) {
        Some(i) if i == "public" => true,
        _ => false
      }) && (
      match endpoint.get("region").and_then(|v| v.as_str()) {
        Some(region) if region == region_name => true,
        _ => false
      })
    })
    .and_then(|endpoint| endpoint.get("url").and_then(|v| v.as_str())).map(|s| s.to_owned())
}

fn get_temp_url_key(info: &SwiftAuthInfo) -> Result<String, Box<Error>> {
  let mut opt_temp_url_key: Option<String> = None;
  let mut easy = Easy::new();
  let mut headers = List::new();
  headers.append("Content-Type: application/json");
  headers.append("Accept: application/json");
  headers.append(& format!("X-Auth-Token: {}", info.token))?;
  headers.append("Expect: ");
  easy.verbose(true);
  easy.post(false);
  easy.url(& format!("{}", info.url))?;
  easy.http_headers(headers);
  {
    let mut transfer = easy.transfer();
    transfer.header_function(|header| {
      let mut splitter = str::from_utf8(header).unwrap().splitn(2, ": ");
      match splitter.next() {
        Some(name) if name.to_lowercase() == "x-account-meta-temp-url-key" => {
          splitter.next().map(|s| s.to_owned()).map(|t| {
            opt_temp_url_key = Some(t.trim().to_owned());
          }); ()
        }
        _ => ()
      }
      true
    })?;
    transfer.perform()?
  }
  opt_temp_url_key
    .ok_or(MissingToken)
    .map_err(|e| From::from(e))
}

fn create_random_key() -> String {
  thread_rng().gen_ascii_chars().take(32).collect()
}

fn set_temp_url_key(info: &SwiftAuthInfo, temp_url_key: &str) -> Result<String, Box<Error>> {
  let mut easy = Easy::new();
  let mut headers = List::new();
  headers.append("Content-Type: application/json");
  headers.append("Accept: application/json");
  headers.append(& format!("X-Auth-Token: {}", info.token))?;
  headers.append(& format!("X-Account-Meta-Temp-Url-Key: {}", temp_url_key));
  headers.append("Expect: ");
  easy.verbose(true);
  easy.post(true);
  easy.url(& format!("{}", info.url))?;
  easy.http_headers(headers);
  easy.perform()?;
  easy.response_code()
    .map_err(|e| From::from(e))
    .and_then(|code| {
      match code {
        200...299 => Ok(temp_url_key.to_owned()),
        _ => Err(From::from(MissingToken))
      }
    })
}
