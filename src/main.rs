#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

mod configuration;

use std::thread::sleep;
use std::time::Duration;

use anyhow::anyhow;
use log::info;
use simplelog::ColorChoice;
use simplelog::Config;
use simplelog::LevelFilter;
use simplelog::TermLogger;
use simplelog::TerminalMode;
use windows_wfp::FilterBuilder;
use windows_wfp::FilterRule;
use windows_wfp::initialize_wfp;
// use windows_wfp::WfpProvider;
// use windows_wfp::WfpSublayer;
use windows_wfp::WfpTransaction;
use windows_wfp::WfpEngine;

use crate::configuration::FilterRuleExt;

fn main() -> anyhow::Result<()>
{
	TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto)?;
	let settings = configuration::get_settings()?;

	let flag = match settings.ephemeral { true => 1, false => 0 }; // FWPM_SESSION_FLAG_DYNAMIC = 1
	let engine = WfpEngine::new_with_flags(flag)?;
	initialize_wfp(&engine)?;
	// WfpProvider::register(&engine)?;
	// WfpSublayer::register(&engine)?;
	let filter_ids = match settings.delete_rule_id
	{
		Some(id) => delete_rule(&engine, id)?,
		None => add_rules(&engine, &settings.rules)?
	};
	info!("Filter IDs processed: {}", filter_ids.iter().map(|id| id.to_string()).collect::<Vec<String>>().join(", "));
	sleep(Duration::from_secs(settings.wait_time));

	return Ok(());
}

fn delete_rule(engine: &WfpEngine, rule_id: u64) -> anyhow::Result<Vec<u64>, anyhow::Error>
{
	info!("Deleting rules...");
	let txn = WfpTransaction::begin(&engine)?;
	let result = match FilterBuilder::delete_filter(&engine, rule_id)
	{
		Ok(_) => Ok(vec![rule_id]),
		Err(err) => Err(anyhow!(err))
	};
	txn.commit()?;
	return result;
	// let mut filter_ids = vec![];
	// let all_rules_installed = FilterEnumerator::all(&engine)?;
	// let txn = WfpTransaction::begin(&engine)?;
	// for rule_installed in all_rules_installed
	// {
	// 	for rule in rules
	// 	{
	// 		let matches_rule = rule.name.eq(&rule_installed.name);
	// 		if !matches_rule { continue; }
	// 		if FilterBuilder::delete_filter(&engine, rule_installed.id).is_err() { continue; }
	// 		filter_ids.push(rule_installed.id);
	// 		info!("\n{}", rule.display_multiline(Some(rule_installed.id)));
	// 	}
	// }
	// txn.commit()?;
	// return Ok(filter_ids);
}

fn add_rules(engine: &WfpEngine, rules: &Vec<FilterRule>) -> anyhow::Result<Vec<u64>>
{
	let mut filter_ids = vec![];
	let txn = WfpTransaction::begin(&engine)?;
	for rule in rules
	{
		let filter_id = FilterBuilder::add_filter(&engine, &rule)?;
		filter_ids.push(filter_id);
		info!("\n{}", rule.display_multiline(Some(filter_id)));
	}
	txn.commit()?;
	return Ok(filter_ids);
}