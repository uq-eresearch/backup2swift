#[macro_use] extern crate clap;
extern crate curl;
extern crate formdata;
extern crate hex;
extern crate hmac;
extern crate hyper;
#[macro_use] extern crate log;
extern crate pipe;
extern crate rand;
extern crate sha_1;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate stderrlog;
extern crate url;

use clap::{Arg, App, SubCommand};
use formdata::{FormData, FilePart, write_formdata};
use hmac::{Hmac, Mac};
use log::LogLevel;
use rand::{thread_rng, Rng};
use hex::ToHex;
use sha_1::Sha1;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::path::Path;
use std::io::{BufReader, BufWriter, Read};
use std::str;
use std::thread::spawn;
use url::Url;

use curl::easy::{Easy, List};

const FORM_MAX_FILE_SIZE: u64 = 1099511627776;
const FORM_MAX_FILE_COUNT: usize = 1048576;
const FORM_EXPIRES: u64 = 4102444800;

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

#[derive(Debug, Serialize, Deserialize)]
struct FormTemplate {
  url: String,
  redirect: String,
  max_file_size: u64,
  max_file_count: usize,
  expires: u64,
  signature: String
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

#[derive(Debug)]
struct MissingTempUrlKey;

impl fmt::Display for MissingTempUrlKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Temp URL key not found in Swift response headers")
  }
}

impl Error for MissingTempUrlKey {
  fn description(&self) -> &str {
    "Temp URL key not found in Swift response headers"
  }

  fn cause(&self) -> Option<&Error> {
    None
  }
}

#[derive(Debug)]
struct UnableToCreateContainer;

impl fmt::Display for UnableToCreateContainer {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Unable to create Swift container")
  }
}

impl Error for UnableToCreateContainer {
  fn description(&self) -> &str {
    "Unable to create Swift container"
  }

  fn cause(&self) -> Option<&Error> {
    None
  }
}

fn main() {
  let matches =
    App::new("backup2swift")
      .version(crate_version!())
      .arg(Arg::with_name("verbosity")
        .short("v")
        .multiple(true)
        .help("Increase message verbosity"))
      .arg(Arg::with_name("quiet")
        .short("q")
        .help("Silence all output"))
      .subcommand(SubCommand::with_name("setup")
        .about("setup container and create request signature")
        .arg(Arg::with_name("container")
          .takes_value(true)
          .required(true)
          .help("destination container name")))
      .subcommand(SubCommand::with_name("backup")
        .about("backup files to container")
        .arg(Arg::with_name("config")
          .short("c")
          .long("config")
          .required(true)
          .takes_value(true)
          .help("JSON config created with \"setup\""))
        .arg(Arg::with_name("delete_after")
          .short("t")
          .long("delete-after")
          .takes_value(true)
          .help("seconds to keep file for"))
        .arg(Arg::with_name("files")
          .takes_value(true)
          .multiple(true)
          .required(true)
          .help("destination container name")))
      .get_matches();
  let verbose = matches.occurrences_of("verbosity") as usize;
  let quiet = matches.is_present("quiet");
  stderrlog::new()
      .module(module_path!())
      .quiet(quiet)
      .verbosity(verbose)
      .init()
      .unwrap();
  if let Some(matches) = matches.subcommand_matches("setup") {
    setup(matches.value_of("container").unwrap());
  } else if let Some(matches) = matches.subcommand_matches("backup") {
    let config = Path::new(matches.value_of("config").unwrap());
    assert!(config.is_file());

    let expire_after = value_t!(matches, "delete_after", u64).ok();
    let file_paths = matches.values_of_lossy("files").unwrap();
    let files: &Vec<&Path> = & file_paths.iter().map(|f| Path::new(f)).collect::<Vec<&Path>>();
    assert!(files.into_iter().all(|f: &&Path| f.is_file()));
    backup(config, expire_after, files);
  } else {
    println!("try 'backup2swift --help' for more information");
    ::std::process::exit(2)
  }
}

fn setup(container_name: &str) -> () {
  let settings = get_os_settings();
  let auth_info = get_token(settings).unwrap();
  let temp_url_key =
    get_temp_url_key(&auth_info)
      .or_else(|_| set_temp_url_key(&auth_info, &create_random_key()))
      .unwrap();
  ensure_container_exists(&auth_info, container_name).unwrap();
  let form_template = backup_config(&auth_info, container_name, &temp_url_key);
  info!("{}", serde_json::to_string_pretty(&form_template).unwrap());
}

fn backup<'a>(
    config_file: &'a Path,
    delete_after: Option<u64>,
    files: &'a Vec<&Path>) -> () {
  let form_template = read_config_file(config_file).unwrap();
  let file_count = files.len();
  info!("{:?}", form_template);
  assert!(form_template.max_file_count >= file_count);
  let file_parts: Vec<(String, FilePart)> =
    files.into_iter()
      .zip(std::ops::Range { start: 0, end: file_count })
      .map(|(f,i): (&&Path, usize)| {
        let mut headers = hyper::header::Headers::new();
        headers.append_raw("Content-Type", "application/octet-stream".to_owned().into_bytes());
        let output: (String, FilePart) = (
          format!("file{}", i),
          formdata::FilePart::new(headers, f)
        );
        output
      })
      .collect::<Vec<(String, FilePart)>>();
  info!("{:?}", file_parts);
  let mut fields = vec![
    ("redirect".to_owned(), form_template.redirect.to_owned()),
    ("max_file_size".to_owned(), format!("{}", form_template.max_file_size)),
    ("max_file_count".to_owned(), format!("{}", form_template.max_file_count)),
    ("expires".to_owned(), format!("{}", form_template.expires)),
    ("signature".to_owned(), format!("{}", form_template.signature))
  ];
  match delete_after {
    Some(n) => fields.push(("x_delete_after".to_owned(), format!("{}", n))),
    None => ()
  };
  let form_data = FormData { fields: fields, files: file_parts };
  send_data(form_template, form_data).unwrap();
}

fn get_env(name: &str) -> String {
  env::var(name).expect(& format!("{} environment variable not defined", name))
}

fn get_os_settings() -> OpenStackConfig {
  let auth_url = get_env("OS_AUTH_URL");
  info!("OS_AUTH_URL: {}", &auth_url);
  let user_domain = get_env("OS_USER_DOMAIN_NAME");
  info!("OS_PROJECT_NAME: {}", &user_domain);
  let username = get_env("OS_USERNAME");
  info!("OS_USERNAME: {}", &username);
  let project_domain = get_env("OS_PROJECT_DOMAIN_NAME");
  info!("OS_PROJECT_NAME: {}", &project_domain);
  let project_name = get_env("OS_PROJECT_NAME");
  info!("OS_PROJECT_NAME: {}", &project_name);
  let password = get_env("OS_PASSWORD");
  info!("OS_PASSWORD: {}", &("*".repeat(password.len())));
  let region_name = get_env("OS_REGION_NAME");
  info!("OS_REGION_NAME: {}",  &region_name);

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
  headers.append("Content-Type: application/json")?;
  headers.append(format!("Content-Length: {}", json_bytes.len()).as_ref())?;
  headers.append("Accept: application/json")?;
  headers.append("Expect: ")?;
  easy.verbose(log_enabled!(LogLevel::Debug))?;
  easy.post(true)?;
  easy.url(& format!("{}auth/tokens", config.auth_url))?;
  easy.http_headers(headers)?;
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
  headers.append(& format!("X-Auth-Token: {}", info.token))?;
  headers.append("Expect: ")?;
  easy.verbose(log_enabled!(LogLevel::Debug))?;
  easy.nobody(true)?;
  easy.url(& format!("{}", info.url))?;
  easy.http_headers(headers)?;
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
  headers.append(& format!("X-Auth-Token: {}", info.token))?;
  headers.append(& format!("X-Account-Meta-Temp-Url-Key: {}", temp_url_key))?;
  headers.append("Expect: ")?;
  easy.verbose(log_enabled!(LogLevel::Debug))?;
  easy.post(true)?;
  easy.url(& format!("{}", info.url))?;
  easy.http_headers(headers)?;
  easy.perform()?;
  easy.response_code()
    .map_err(|e| From::from(e))
    .and_then(|code| {
      match code {
        200...299 => Ok(temp_url_key.to_owned()),
        _ => Err(From::from(MissingTempUrlKey))
      }
    })
}

fn ensure_container_exists(info: &SwiftAuthInfo, container: &str) -> Result<(), Box<Error>> {
  let mut easy = Easy::new();
  let mut headers = List::new();
  headers.append(& format!("X-Auth-Token: {}", info.token))?;
  headers.append("Expect: ")?;
  easy.verbose(log_enabled!(LogLevel::Debug))?;
  easy.nobody(true)?;
  easy.url(& format!("{}/{}", info.url, container))?;
  easy.http_headers(headers)?;
  easy.perform()?;
  easy.response_code()
    .map_err(|e| From::from(e))
    .and_then(|code| {
      match code {
        200...299 => Ok(()),
        _ => create_container(info, container)
      }
    })
}

fn create_container(info: &SwiftAuthInfo, container: &str) -> Result<(), Box<Error>> {
  let mut easy = Easy::new();
  let mut headers = List::new();
  headers.append("Content-Length: 0")?;
  headers.append(& format!("X-Auth-Token: {}", info.token))?;
  headers.append("Expect: ")?;
  easy.verbose(log_enabled!(LogLevel::Debug))?;
  easy.put(true)?;
  easy.url(& format!("{}/{}", info.url, container))?;
  easy.http_headers(headers)?;
  easy.perform()?;
  easy.response_code()
    .map_err(|e| From::from(e))
    .and_then(|response_code| {
      match response_code {
        200...299 => Ok(()),
        _ => Err(From::from(UnableToCreateContainer))
      }
    })
}

fn form_post_url(info: &SwiftAuthInfo, container: &str) -> Url {
  Url::parse(& format!("{}/{}/", info.url, container)).unwrap()
}

fn signature(
    signature_path: &str,
    redirect: &str,
    max_file_size: &u64,
    max_file_count: &usize,
    expires: &u64,
    temp_url_key: &str) -> String {
  let input = format!(
    "{}\n{}\n{}\n{}\n{}",
    signature_path,
    redirect,
    max_file_size,
    max_file_count,
    expires
  );
  // Create `Mac` trait implementation, namely HMAC-SHA256
  let mut mac = Hmac::<Sha1>::new(temp_url_key.as_bytes());
  mac.input(input.as_bytes());
  mac.result().code().to_hex()
}

fn backup_config(info: &SwiftAuthInfo, container: &str, temp_url_key: &str) -> FormTemplate {
  let url: Url = form_post_url(info, container);
  let redirect = "";
  let max_file_size = FORM_MAX_FILE_SIZE;
  let max_file_count = FORM_MAX_FILE_COUNT;
  let expires = FORM_EXPIRES;
  FormTemplate {
    url: url.as_str().to_owned(),
    redirect: redirect.to_owned(),
    max_file_size: max_file_size,
    max_file_count: max_file_count,
    expires: expires,
    signature: signature(
      url.path(),
      redirect,
      &max_file_size,
      &max_file_count,
      &expires,
      temp_url_key)
  }
}

fn read_config_file<'a>(config_file: &'a Path) -> Result<FormTemplate, Box<Error>> {
  let f = File::open(config_file)?;
  let rdr = BufReader::new(f);
  serde_json::from_reader(rdr).map_err(|e| From::from(e))
}

fn send_data(form_template: FormTemplate, form_data: FormData) -> Result<(), Box<Error>> {
  let mut headers = List::new();
  let boundary_str: &str = & {
    let rand_str: String = thread_rng().gen_ascii_chars().take(20).collect();
    "-".repeat(20).to_string() + &rand_str
  };
  let boundary: Vec<u8> = boundary_str.to_owned().into_bytes();
  let mut sink = std::io::sink();
  let content_length = write_formdata(&mut sink, &boundary, &form_data)?;
  headers.append(& format!("Content-Length: {}", content_length))?;
  headers.append(& format!("Content-Type: multipart/form-data; boundary={}", boundary_str))?;
  let mut easy = Easy::new();
  easy.verbose(log_enabled!(LogLevel::Debug))?;
  easy.post(true)?;
  easy.url(& form_template.url)?;
  easy.http_headers(headers)?;
  {
    const BUFFER_SIZE: usize = 524288;
    let (r, w) = pipe::pipe();
    let mut br = BufReader::with_capacity(BUFFER_SIZE, r);
    let mut bw = BufWriter::with_capacity(BUFFER_SIZE, w);
    spawn(move || write_formdata(&mut bw, &boundary, &form_data));
    let mut transfer = easy.transfer();
    transfer.read_function(|into| {
      Ok(br.read(into).unwrap_or(0))
    })?;
    transfer.perform()?;
  }
  Ok(())
}
