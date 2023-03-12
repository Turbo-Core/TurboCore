use serde_json::json;
use sysinfo::{CpuExt, System, SystemExt, DiskExt};

pub fn sysinfo(sys: &mut System) -> String {
	sys.refresh_all();
	let cpu = sys.cpus().iter().map(|cpu| {
		json!({
			"name": cpu.brand(),
			"usage": cpu.cpu_usage(),
		})
	});
	let disk = sys.disks().iter().map(|disk| {
        json!({
            "name": (*disk.name()).to_str(),
            "total": disk.total_space(),
            "free": disk.available_space()
        })
    });

	format!(
		"{{
                \"cpus\": {},
                \"mem\": {{
                    \"total\": {},
                    \"used\": {},
                    \"free\": {},
                    \"swap_total\": {},
                    \"swap_used\": {},
                    \"swap_free\": {}
                }},
                \"disks\": {}",
		serde_json::to_string(&cpu.collect::<Vec<_>>()).unwrap(),
		sys.total_memory(),
		sys.used_memory(),
		sys.free_memory(),
		sys.total_swap(),
		sys.used_swap(),
		sys.free_swap(),
        serde_json::to_string(&disk.collect::<Vec<_>>()).unwrap(),
	)
}
