import streamlit as st
import pandas as pd
import json
from datetime import datetime
from pathlib import Path
from scanner import (
    generate_pdf_report,
    map_services_to_advisories,
    resolve_nmap_command,
    run_modules,
    run_nmap_scan,
)


HISTORY_FILE = Path("exports/scan_history.json")


def load_scan_history() -> list[dict]:
    """Load persisted scan history from disk."""
    try:
        if not HISTORY_FILE.exists():
            return []
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_scan_history(history: list[dict]) -> None:
    """Persist scan history to disk."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)


def do_scan(target: str, speed: str, scan_mode: str):
    """Run the nmap scan and modules, persist results into session state."""
    if not target:
        st.error("Please enter a target!")
        return

    with st.spinner(f"Scanning {target}... This may take a minute."):
        try:
            profile = "health" if scan_mode == "Health Checks (Fast)" else "full"
            scan_results = run_nmap_scan(target, speed, profile)
        except Exception as exc:
            st.error(f"Scan failed: {exc}")
            return

        if not scan_results:
            st.warning("No open ports found or target unreachable.")
            return

        advisories = map_services_to_advisories(scan_results)
        module_outputs = run_modules(target, scan_results)

        st.session_state["last_target"] = target
        st.session_state["last_scan_results"] = scan_results
        st.session_state["last_advisories"] = advisories
        st.session_state["last_module_outputs"] = module_outputs
        st.session_state["last_scan_mode"] = scan_mode
        st.session_state["last_speed"] = speed

        st.session_state["scan_history"].append(
            {
                "scan_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "target": target,
                "scan_mode": scan_mode,
                "speed": speed,
                "open_service_count": len(scan_results),
                "advisory_count": len(advisories),
                "services": scan_results,
                "advisories": advisories,
            }
        )
        save_scan_history(st.session_state["scan_history"])

st.set_page_config(page_title="X-RECON Defensive Auditor", layout="wide")

nmap_command = resolve_nmap_command()

st.title("X-RECON Defensive Asset Auditor")
st.markdown("Authorized service discovery, advisory mapping, and hardening checks.")

# Sidebar
st.sidebar.header("Scan Settings")
target = st.sidebar.text_input("Target IP or Domain")
speed = st.sidebar.selectbox("Timing Profile", ["-T1", "-T2", "-T3", "-T4", "-T5"], index=3)
scan_mode = st.sidebar.selectbox(
    "Scan Mode",
    ["Full Service Audit", "Health Checks (Fast)"],
    index=0,
)

if nmap_command:
    st.sidebar.success(f"Nmap ready: {nmap_command}")
else:
    st.sidebar.error("Nmap not found. Install it or set NMAP_PATH to nmap.exe.")

if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = load_scan_history()

if st.sidebar.button("Reload History"):
    st.session_state["scan_history"] = load_scan_history()
    st.sidebar.success("History reloaded from disk.")

if st.sidebar.button("Clear History"):
    st.session_state["scan_history"] = []
    save_scan_history([])
    st.sidebar.success("History cleared.")

if st.sidebar.button("Launch Scan", disabled=not nmap_command):
    do_scan(target, speed, scan_mode)

scan_results = st.session_state.get("last_scan_results", []) 
advisories = st.session_state.get("last_advisories", [])
module_outputs = st.session_state.get("last_module_outputs", {})
last_target = st.session_state.get("last_target", "")
last_scan_mode = st.session_state.get("last_scan_mode", "")
last_speed = st.session_state.get("last_speed", "")
history = st.session_state.get("scan_history", [])

if not scan_results:
    st.header("Welcome to X-RECON")
    st.markdown(
        "This tool performs authorized defensive service discovery and maps findings to local advisories.\n\n"
        "Enter a target in the sidebar and press **Launch Scan** to begin.\n\n"
        "You can also run a quick example scan against a public test target."
    )

    c_left, c_mid, c_right = st.columns([1, 2, 1])
    with c_mid:
        if st.button("Run Example Scan (scanme.nmap.org)", key="example_scan"):
            # prefill the target and run
            st.session_state["last_target"] = "scanme.nmap.org"
            do_scan("scanme.nmap.org", speed, scan_mode)

    # show small recent history
    if history:
        st.subheader("Recent Scans")
        recent = pd.DataFrame(
            [
                {"Scan ID": h["scan_id"], "Target": h["target"], "Time": h["timestamp"]}
                for h in history[-5:]
            ]
        )
        st.table(recent)

else:
    tab1, tab2, tab3, tab4 = st.tabs(
        ["Discovered Services", "Advisory Matches", "Module Outputs", "History & Compare"]
    )

    with tab1:
        df = pd.DataFrame(scan_results)
        st.dataframe(df, use_container_width=True)

    with tab2:
        if advisories:
            st.dataframe(pd.DataFrame(advisories), use_container_width=True)
        else:
            st.info("No advisory matches were found in the local knowledge base.")

    with tab3:
        for module_name, rows in module_outputs.items():
            st.subheader(module_name.capitalize())
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
            else:
                st.write("No findings.")

    with tab4:
        if history:
            history_table = pd.DataFrame(
                [
                    {
                        "Scan ID": item["scan_id"],
                        "Timestamp": item["timestamp"],
                        "Target": item["target"],
                        "Mode": item["scan_mode"],
                        "Speed": item["speed"],
                        "Open Services": item["open_service_count"],
                        "Advisories": item["advisory_count"],
                    }
                    for item in history
                ]
            )
            st.dataframe(history_table, use_container_width=True)

            if len(history) >= 2:
                labels = [
                    f"{item['scan_id']} | {item['timestamp']} | {item['target']} | {item['scan_mode']}"
                    for item in history
                ]
                left_label = st.selectbox("Baseline scan", labels, index=max(0, len(labels) - 2))
                right_label = st.selectbox("Comparison scan", labels, index=len(labels) - 1)

                left_idx = labels.index(left_label)
                right_idx = labels.index(right_label)
                left_services = history[left_idx]["services"]
                right_services = history[right_idx]["services"]

                left_set = {
                    (
                        s.get("port", ""),
                        s.get("protocol", ""),
                        s.get("name", ""),
                        s.get("product", ""),
                        s.get("version", ""),
                    )
                    for s in left_services
                }
                right_set = {
                    (
                        s.get("port", ""),
                        s.get("protocol", ""),
                        s.get("name", ""),
                        s.get("product", ""),
                        s.get("version", ""),
                    )
                    for s in right_services
                }

                added = right_set - left_set
                removed = left_set - right_set

                st.subheader("Service Diff")
                st.write(f"New services in comparison scan: {len(added)}")
                if added:
                    st.dataframe(
                        pd.DataFrame(
                            added,
                            columns=["port", "protocol", "name", "product", "version"],
                        ),
                        use_container_width=True,
                    )

                st.write(f"Services no longer visible: {len(removed)}")
                if removed:
                    st.dataframe(
                        pd.DataFrame(
                            removed,
                            columns=["port", "protocol", "name", "product", "version"],
                        ),
                        use_container_width=True,
                    )
        else:
            st.info("No scan history yet. Run at least one scan.")

    export_payload = {
        "target": last_target,
        "scan_mode": last_scan_mode,
        "speed": last_speed,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "services": scan_results,
        "advisories": advisories,
        "module_outputs": module_outputs,
    }
    services_csv = pd.DataFrame(scan_results).to_csv(index=False).encode("utf-8")
    advisories_csv = pd.DataFrame(advisories).to_csv(index=False).encode("utf-8")
    export_json = json.dumps(export_payload, indent=2).encode("utf-8")

    st.markdown("### Exports")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            label="Download Services CSV",
            data=services_csv,
            file_name=f"services_{last_target}.csv",
            mime="text/csv",
        )
    with c2:
        st.download_button(
            label="Download Advisories CSV",
            data=advisories_csv,
            file_name=f"advisories_{last_target}.csv",
            mime="text/csv",
        )
    with c3:
        st.download_button(
            label="Download Full JSON",
            data=export_json,
            file_name=f"report_{last_target}.json",
            mime="application/json",
        )

    if st.button("Generate PDF Report"):
        pdf_path = generate_pdf_report(last_target, scan_results, advisories, module_outputs)
        with open(pdf_path, "rb") as report_file:
            st.download_button(
                label="Download Report",
                data=report_file.read(),
                file_name=pdf_path.split("/")[-1].split("\\")[-1],
                mime="application/pdf",
            )

# Footer
st.sidebar.markdown("---")
st.sidebar.caption("For authorized defensive assessments only.")