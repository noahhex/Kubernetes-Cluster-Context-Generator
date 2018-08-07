extern crate openssl;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509VerifyResult};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
                               SubjectAlternativeName, SubjectKeyIdentifier};

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
use std::collections::HashMap;

const REGION: &str = "";
const BUCKET: &str = "";



fn get_ca_from_s3(home: &str) -> Result<(), Error> {
	let credentials = Credentials::new(Some(String::from(""))
	,Some(String::from("")),None,None);

	let first_arg = format!("{}/.certs/kubernetes/pki/ca.crt", home);
	let second_arg = format!("{}/.certs/kubernetes/pki/ca.key", home);
	let region = REGION.parse().unwrap();
	let bucket = Bucket::new(BUCKET, region, credentials);

	let (data, code) = bucket.get("cluster-1.citizenhex-sandbox.co.uk/pki/issued/ca/6584084891014744288690932805.crt").unwrap();
	let mut crt = File::create(&first_arg)?;
	crt.write(&data)?;

	let (data, code) = bucket.get("cluster-1.citizenhex-sandbox.co.uk/pki/private/ca/6584084891014744288690932805.key").unwrap();
	let mut key = File::create(&second_arg)?;
	key.write(&data)?;

	Ok(())
}


fn setup_home(home: &str) -> Result<(),()> {
	let tmp_home = home;
	let first_arg = format!(" {}/.certs/Citizen Hex/", tmp_home);
	let second_arg = format!(" {}/.certs/kubernetes/pki/", tmp_home);

	Ok(())
}


fn gen_ssl_cert(name: &str,home: &str) -> Result<(), Error> {
	let users: HashMap<&str,&str> = [("ben","auditor"),("brett","auditor"),("noah","admin"),
	("will","dev"),("rohit","dev"),("david","dev")].iter().cloned().collect();
	        
	match users.get(name) {
		Some(&"dev")  => {
			gen_ssl_wrapper(name, home, "dev")			
		},
		Some(&"admin") => {
			gen_ssl_wrapper(name, home, "admin")
		},
		Some(&"auditor") => {
			gen_ssl_wrapper(name, home, "auditor")
		},
		_ => (),
	}
	
	Ok(())
}


fn gen_key(name: &str, home: &str) -> PKey<Private> {
	let first_arg = format!("{}/.certs/employee-{}.key", home, name);
	let mut f = File::create(&first_arg).unwrap();
	let rsa = Rsa::generate(4096).unwrap();
	let privkey = PKey::from_rsa(rsa).unwrap();
	let key = privkey.private_key_to_pem_pkcs8().unwrap(); 
	f.write(&key).unwrap();
	privkey
	
}


fn gen_request(privkey: &PKey<Private>, name: &str, org: &str) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&privkey)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("O", org)?;
    x509_name.append_entry_by_text("CN", name)?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(&privkey, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

fn gen_signed_cert(ca_cert: &X509Ref,ca_privkey: &PKeyRef<Private>, name: &str, home: &str, org: &str) -> Result<X509, ErrorStack> {
	let key = gen_key(name, home);
    let req = gen_request(&key, name, org)?;
	
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&key)?;

    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;

    let not_after = Asn1Time::days_from_now(365)?;
	cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(KeyUsage::new()
        .critical()
        .non_repudiation()
        .digital_signature()
        .key_encipherment()
        .build()?)?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;


    cert_builder.sign(&ca_privkey, MessageDigest::sha256())?;

    let cert = cert_builder.build();
    let first_arg = format!("{}/.certs/Citizen Hex/employee-{}.crt", home, name);
	let mut cert_file = File::create(&first_arg).unwrap();
	let mut cert_bytes = cert.to_pem().unwrap();
	cert_file.write(&mut cert_bytes);
	
    Ok(cert)
}


fn gen_ssl_wrapper(name: &str, home: &str, org: &str) {
	let first_arg = format!("{}/.certs/kubernetes/pki/ca.crt", home);
	let second_arg = format!("{}/.certs/kubernetes/pki/ca.key", home);
	
	let mut cert = File::open(&first_arg).unwrap();
	let mut cert_buf: Vec<u8> = Vec::new();
	cert.read_to_end(&mut cert_buf).unwrap();	
	let ca = X509::from_pem(&cert_buf).unwrap();
	
	let mut key = File::open(&second_arg).unwrap();
	let mut key_buf: Vec<u8> = Vec::new();
	key.read_to_end(&mut key_buf).unwrap();
	let key_ref = PKey::private_key_from_pem(&key_buf).unwrap();

	gen_signed_cert(&ca, &key_ref, name, home, org).unwrap();
	
}

fn main() {
	let arguments: Vec<String> = args().collect();
	let name: &str = &arguments[1];
	let tmp_home = home_dir().unwrap();
	let home = tmp_home.to_str().unwrap();
//	let kubernetes_cluster_url = &arguments[2];
	setup_home(home).unwrap();
	get_ca_from_s3(home).unwrap();
	gen_ssl_cert(name, home).unwrap();
//	set_kubernetes_context(noah, home, kuberntes_cluster_url)?;
}
