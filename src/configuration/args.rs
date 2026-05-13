#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

use std::path::PathBuf;

use anyhow::anyhow;
use clap::ArgMatches;
use windows_wfp::Direction;
use windows_wfp::FilterWeight;
use windows_wfp::Action;
use windows_wfp::IpAddrMask;

pub(crate) fn get_rule_from_args(matches: ArgMatches) -> Result<Option<windows_wfp::FilterRule>, anyhow::Error>
{
	let name = match matches.get_one::<String>("name")
	{
		None => return Ok(None),
		Some(name) => name
	};
	let direction = match matches.get_flag("inbound")
	{
		true => Direction::Inbound,
		false => Direction::Outbound
	};
	let filter_type = match matches.get_flag("permit")
	{
		true => Action::Permit,
		false => Action::Block
	};

	let mut filter = windows_wfp::FilterRule::new(name, direction, filter_type);
	filter.service_name = match matches.get_one::<String>("service_name")
	{
		None => None,
		Some(name) => match name.as_str()
		{
			"" => None,
			_ => Some(name.clone())
		}
	};
	filter.remote_ip = match matches.get_one::<String>("remote_ip")
	{
		None => None,
		Some(ip) => match IpAddrMask::from_cidr(ip)
		{
			Ok(ip) => Some(ip),
			Err(err_msg) => { return Err(anyhow!(err_msg)); }
		}
	};
	filter.weight = match matches.get_one::<String>("weight")
	{
		None =>
		{
			match filter_type
			{
				Action::Permit => FilterWeight::DefaultPermit.value(),
				Action::Block => FilterWeight::DefaultBlock.value()
			}
		}
		Some(w) =>
			{
				if w == "MAX" { u64::MAX }
				else { w.parse::<u64>()? }
			}
	};
	filter.app_path = match matches.get_one::<String>("app_path")
	{
		None => None,
		Some(path) => match path.as_str() { "" => None, _ => Some(PathBuf::from(path)) }
	};

	return Ok(Some(filter));
}