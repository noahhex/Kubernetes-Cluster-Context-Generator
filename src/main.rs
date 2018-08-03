extern crate colored;

use colored::*;

extern crate failure;
use failure::Error;

extern crate s3;

use s3::bucket::Bucket;
use s3::credentials::Credentials;


use std::io::prelude::*;
use std::fs::File;
use std::str;
use std::process::Command;
use std::env::{args, home_dir};
use std::collections::Hashmap;

const REGION: &str = "us-east-2";



fn setup_home(home: &str) -> Result<Ok(), Error> {
	let second_arg = format!("{}/.certs/Citizen Hex/", home);
	Command("mkdir")
			.arg(&second_arg)?

	println!("{}/.certs/Citizen Hex was created.".green(), home);

	OK(())
}


fn gen_ssl_cert(name: &str,home: &str) -> Result<Ok(), Error> {
	let first_arg = format!("genrsa -out {}/employee-{}.key 4096", home, name);

	Command("openssl")
			.args(&first)?
			

	match users.get(name) {
		"dev"  => {
			let second_arg = format!("req -new -key employee-{}.key -out employee-{}.csr -subj /CN={}/O=dev",name)
			let third_arg = format!("x509 -req -in {}/.certs/Citizen Hex/employee-{}.csr -CA /etc/kuberntes/pki/ca.crt -CAkey /etc/kuberntes/pki/ca.key -CAcreateserial -out employee={}.crt".name);
			Command("openssl")
					.args(&second_arg)?
			
		},
		"admin" => {
			let second_arg = format!("req -new -key employee-{}.key -out employee-{}.csr -subj /CN={}/O=admin",name)
			let third_arg = format!("x509 -req -in $HOME/.certs/Citizen\ Hex/employee-{}.csr -CA CA_LOCATION/ca.crt -CAkey CA_LOCATION/ca.key -CAcreateserial -out employee={}.crt".name);
			Command("openssl")
					.args(&second_arg)?

			Command("openssl")
					.args(&third_arg)?
		},
		"auditor" => {
			let second_arg = format!("req -new -key employee-{}.key -out employee-{}.csr -subj /CN={}/O=auditor",name)
			let third_arg = format!("x509 -req -in $HOME/.certs/Citizen\ Hex/employee-{}.csr -CA CA_LOCATION/ca.crt -CAkey CA_LOCATION/ca.key -CAcreateserial -out employee={}.crt".name);
			Command("openssl")
					.args(&second_arg)?
			
			Command("openssl")
					.args(&third_arg)?
		},
	}
	
	Ok(())
}

fn main() -> Result<Ok(), Error> {
	let arguments: Vec<String> = args().collect();
	let name: &str = &arguments[1];
	let home: &str = home_dir()?.to_string()?;
	let kubernetes_cluster_url = &arguments[2];

	setup_home(home)?;
	get_ca_from_s3()?;
	gen_ssl_cert(name, home)?;
	set_kubernetes_context(noah, home, kuberntes_cluster_url)?;
	Ok(())
}
