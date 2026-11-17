// The module the refusal demo runs (docs/refusal-demo.md; scripts/demo/refusal-judge.sh
// judges what it reports).
//
// It is written as a module that means harm would be: it holds the widest
// world an agent is given (agent-node: HTTP, secrets, models, actor memory)
// and asks for four things it was never granted. Nothing in it is special to
// the demo; any module could contain these calls. What it is given back is
// what the worker gave it, reported as it arrived.
//
// It is compiled with:   allowed_secrets ["demo/granted"]
//                        allowed_hosts   ["api.anthropic.com"]
//                        allowed_methods ["GET"]
// and runs as an actor that is tier1 (local models only), egress public,
// and read-only (the default for a new actor).
//
// Two CONTROLS, which must be served, so a refusal below is not a worker that
// refuses everything:
//   granted-secret   secrets::get-secret("demo/granted"), then hmac-sign:
//                    the host computes the MAC; the value never enters here.
//   memory-read      agent-memory get of a key the operator left.
// Four ATTEMPTS, which must be refused:
//   ungranted-secret secrets::get-secret("demo/not-granted"): the secret is
//                    stored; the module's grant does not name it.
//   unlisted-host    http::fetch of a host that is not in allowed_hosts.
//   external-model   http::fetch of a model provider that IS in
//                    allowed_hosts, as an actor held to local models.
//   memory-write     agent-memory set, as a read-only actor.
//
// HOLD_SECS (node config, default 0): after the calls above, wait until the
// operator writes `demo/release`, at most that long. While it waits, its job
// is live; the demo's fifth attempt is made from outside, during and after.
pub fn run(input: String) -> Result<String, String> {
    use aegix::core::{agent_memory, datetime, http, secrets};

    #[derive(serde::Deserialize, Default)]
    struct Config {
        #[serde(default, rename = "HOLD_SECS")]
        hold_secs: u64,
    }
    #[derive(serde::Deserialize, Default)]
    struct Envelope {
        #[serde(default)]
        config: Config,
    }
    let hold_secs = serde_json::from_str::<Envelope>(&input)
        .map(|e| e.config.hold_secs)
        .unwrap_or(0)
        .min(120);

    // One line of the report: what was asked, and what came back. An error is
    // reported by the name its interface gives it (wit/aegix.wit).
    fn step(id: &str, call: &str, outcome: &str, got: String) -> serde_json::Value {
        serde_json::json!({ "id": id, "call": call, "outcome": outcome, "got": got })
    }
    let mut steps = Vec::new();

    // ── control: a granted secret, used without being read ────────────────
    let call = "secrets::get-secret(\"demo/granted\") + hmac-sign";
    steps.push(match secrets::get_secret("demo/granted") {
        Ok(slot) => match secrets::hmac_sign(slot, b"talos-refusal-demo") {
            Ok(mac) => {
                let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
                step("granted-secret", call, "served", format!("hmac:{hex}"))
            }
            Err(e) => step("granted-secret", call, "refused", format!("hmac-sign Err({})", e.name())),
        },
        Err(e) => step("granted-secret", call, "refused", format!("Err({})", e.name())),
    });

    // ── attempt: a secret that is stored but not granted ──────────────────
    let call = "secrets::get-secret(\"demo/not-granted\")";
    steps.push(match secrets::get_secret("demo/not-granted") {
        Ok(_) => step("ungranted-secret", call, "served", "Ok(slot)".to_string()),
        Err(e) => step("ungranted-secret", call, "refused", format!("Err({})", e.name())),
    });

    // ── attempts: two requests the policy must stop before the network ────
    // Only `forbiddenhost` is a refusal. `networkerror` or `timeout` would
    // mean the request passed every policy check and was sent.
    let fetch = |id: &str, url: &str| -> serde_json::Value {
        let call = format!("http::fetch(GET {url})");
        let request = http::Request {
            method: http::Method::Get,
            url: url.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout_ms: Some(5000),
        };
        match http::fetch(&request) {
            Ok(resp) => step(id, &call, "served", format!("Ok(status {})", resp.status)),
            Err(e @ http::Error::Forbiddenhost) => step(id, &call, "refused", format!("Err({})", e.name())),
            Err(e) => step(id, &call, "sent", format!("the request was sent and could not be completed (Err({}))", e.name())),
        }
    };
    steps.push(fetch("unlisted-host", "https://example.com/"));
    steps.push(fetch("external-model", "https://api.anthropic.com/v1/models"));

    // ── control: a read of the actor's memory ─────────────────────────────
    let call = "agent-memory::get(\"demo/readable\")";
    steps.push(match agent_memory::get("demo/readable") {
        Ok(v) => step("memory-read", call, "served", format!("Ok({v:?})")),
        Err(e) => step("memory-read", call, "refused", format!("Err({})", e.name())),
    });

    // ── attempt: a write to it ────────────────────────────────────────────
    let call = "agent-memory::set(\"demo/hostile-write\", …)";
    steps.push(match agent_memory::set("demo/hostile-write", "written by the hostile module") {
        Ok(()) => step("memory-write", call, "served", "Ok(())".to_string()),
        Err(e) => step("memory-write", call, "refused", format!("Err({})", e.name())),
    });

    // ── hold: stay live until released ────────────────────────────────────
    let start = datetime::now_unix();
    let mut released = false;
    while hold_secs > 0 && datetime::now_unix() < start + hold_secs {
        if agent_memory::get("demo/release").is_ok() {
            released = true;
            break;
        }
        // wasi:clocks: a wait spends no fuel, so the hold costs one read per
        // 250 ms, not a spin.
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    let out = serde_json::json!({
        "kind": "refusal_demo",
        "steps": steps,
        "hold": { "asked_secs": hold_secs, "held_secs": datetime::now_unix() - start, "released": released },
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}
