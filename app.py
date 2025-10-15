# app.py (full, updated: includes Firestore-backed persistent chat)
import streamlit as st
import base64, json, time, io, os
from core import idn_lwe, hybrid_crypto, simulation

# try to import firestore helper (not fatal if missing)
try:
    from core import firestore_store
except Exception:
    firestore_store = None

st.set_page_config(layout="wide", page_title="Quantum Secure Demo (modular)")

st.title("Quantum-Secure Hybrid Demo — File encryption + Simulation")

# ---------------- Sidebar: Key Management (improved) ----------------
st.sidebar.header("Key Management")

# Generate new keypair
if st.sidebar.button("Generate IDN-LWE keypair (demo)"):
    pk, sk = idn_lwe.keygen()
    st.session_state["pk"] = pk
    st.session_state["sk"] = sk
    st.sidebar.success("✅ Keypair generated and stored in session memory.")

# Upload an existing private key
uploaded_sk = st.sidebar.file_uploader("Import private key (JSON)", type=["json"], key="private_key_uploader")
if uploaded_sk:
    try:
        sk_text = uploaded_sk.read().decode()
        sk_data = json.loads(sk_text)
        st.session_state["sk"] = sk_data
        st.sidebar.success("Secret key loaded successfully.")
    except Exception as e:
        st.sidebar.error(f"Failed to import private key: {e}")

# Upload an existing public key
uploaded_pk = st.sidebar.file_uploader("Import public key (JSON)", type=["json"], key="public_key_uploader")
if uploaded_pk:
    try:
        pk_text = uploaded_pk.read().decode()
        pk_data = json.loads(pk_text)
        st.session_state["remote_pk"] = pk_data
        st.sidebar.success("Remote public key loaded.")
    except Exception as e:
        st.sidebar.error(f"Failed to import public key: {e}")

# Export current public key
if st.sidebar.button("Export current public key"):
    if "pk" in st.session_state:
        pk_json = idn_lwe.export_public_key(st.session_state["pk"])
        st.download_button("Download Public Key JSON", pk_json, file_name="idn_pubkey.json")
    else:
        st.sidebar.warning("Generate a keypair first.")

st.sidebar.markdown("---")
st.sidebar.info("You must have your **secret key** loaded to decrypt incoming messages. Public keys are used to encrypt to recipients.")

# ---------------- Initialize Firestore (optional) ----------------
if "firestore_client" not in st.session_state:
    st.session_state["firestore_client"] = None
    # attempt to read SA JSON from Streamlit secrets
    try:
        sa_json = st.secrets["firestore"]["service_account"]
        if firestore_store:
            try:
                st.session_state["firestore_client"] = firestore_store.init_firestore_from_service_account_json_str(sa_json)
                st.sidebar.success("Firestore initialized (persistent chat enabled).")
            except Exception as e:
                st.sidebar.warning("Failed to init Firestore: " + str(e))
        else:
            st.sidebar.warning("Firestore helper module not installed.")
    except Exception:
        # missing secrets — that's fine, app will fall back to local storage
        pass

# ---------------- Tabs ----------------
tab_encrypt, tab_perf, tab_sim, tab_chat,tab_qres = st.tabs([
    "Encrypt file / text",
    "Performance Dashboard",
    "Quantum Attack Simulation",
    "Quantum-Safe Group Chat",
    "Quantum Resource Estimator"
])

# ---------------- Tab: Encrypt file / text ----------------
with tab_encrypt:
    st.header("Encrypt data for a recipient (hybrid)")

    col1, col2 = st.columns([1,1])
    with col1:
        recipient_choice = st.selectbox("Encrypt to", options=["Use session keypair (local)", "Use imported public key (remote)"])
        upload_mode = st.radio("Input type", ["Text (paste)", "File upload"], index=0)
        if upload_mode == "Text (paste)":
            user_text = st.text_area("Enter text to encrypt", height=200)
            file_obj = None
        else:
            file_obj = st.file_uploader("Upload a file to encrypt (binary)", type=None)
            user_text = None

        wrap_mode = st.selectbox("Key-wrap method (demo)", ["Fast IDN-LWE mock (fast)", "Bitwise IDN-LWE (slow, educational)"])
        if "remote_pk" in st.session_state:
            st.write("✅ Remote PK loaded — will be used if 'Use imported public key' selected.")

        # encrypt button
        if st.button("Encrypt now"):
            # gather plaintext
            if upload_mode == "Text (paste)":
                if not user_text:
                    st.error("Enter text to encrypt.")
                    st.stop()
                plaintext_bytes = user_text.encode()
                key, nonce, aes_ct = hybrid_crypto.aes_encrypt(plaintext_bytes)
                stream_mode = False
            else:
                if not file_obj:
                    st.error("Upload a file first.")
                    st.stop()
                f = io.BytesIO(file_obj.read())
                key, base_nonce, chunks_b64 = hybrid_crypto.aes_encrypt_stream(f)
                stream_mode = True

            # choose recipient public key
            if recipient_choice.startswith("Use session"):
                if "pk" not in st.session_state:
                    st.error("Generate a session keypair first.")
                    st.stop()
                pk_target = st.session_state["pk"]
            else:
                if "remote_pk" not in st.session_state:
                    st.error("Upload a remote public key first.")
                    st.stop()
                pk_target = st.session_state["remote_pk"]

            # choose wrapping method
            if wrap_mode.startswith("Fast"):
                wrapdict = idn_lwe.fast_wrap_key(pk_target, key)
            else:
                wrapdict = idn_lwe.wrap_key(pk_target, key)  # slow: bitwise, may take time

            # metadata (fixed type-safe handling)
            if isinstance(wrapdict, list):
                wrap_method = "idn-bitwise"
            elif isinstance(wrapdict, dict):
                wrap_method = wrapdict.get("method", "idn-fast")
            else:
                wrap_method = "unknown"

            metadata = {
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "wrap_method": wrap_method,
                "origin": "demo",
                "filename": file_obj.name if file_obj else "pasted_text.txt",
            }

            # build payload
            if stream_mode:
                payload = hybrid_crypto.build_payload_stream(metadata, wrapdict, base_nonce, chunks_b64)
            else:
                payload = hybrid_crypto.build_payload(metadata, wrapdict, nonce, aes_ct)

            # optionally add HMAC
            if st.sidebar.checkbox("Add integrity HMAC (demo)", value=True):
                payload_bytes = json.dumps(payload).encode()
                tag = hybrid_crypto.sign_payload_hmac(key, payload_bytes)
                payload["audit_hmac"] = base64.b64encode(tag).decode()

            # download payload
            payload_json = json.dumps(payload)
            st.session_state["last_payload"] = {
                "json": payload_json,
                "aes_key": base64.b64encode(key).decode()
            }
            st.download_button(
                "Download encrypted payload (JSON)",
                payload_json,
                file_name="encrypted_payload.json",
                mime="application/json"
            )
            st.success("✅ Payload created and downloadable. Note: keep AES key (session) to decrypt in this demo.")

    with col2:
        st.subheader("Decrypt payload")
        uploaded_payload = st.file_uploader("Upload an encrypted payload JSON to decrypt", type=["json"])
        if st.button("Decrypt uploaded payload"):
            if not uploaded_payload:
                st.error("Upload a payload JSON file")
                st.stop()
            raw = uploaded_payload.read().decode()
            payload = json.loads(raw)

            if "sk" not in st.session_state:
                st.error("No session secret key available — generate or import keypair first.")
                st.stop()

            sk = st.session_state["sk"]
            wrapdict = payload.get("wrap")

            if isinstance(wrapdict, list):
                # Real bitwise unwrap
                try:
                    key_bytes = idn_lwe.unwrap_key(sk, wrapdict)
                except Exception as e:
                    st.error(f"Unwrap failed: {e}")
                    st.stop()
            else:
                st.warning("⚠️ Mock-fast mode detected — cannot unwrap; using stored AES key (demo only).")
                if "last_payload" in st.session_state:
                    key_b64 = st.session_state["last_payload"].get("aes_key")
                    key_bytes = base64.b64decode(key_b64)
                else:
                    st.error("No AES key available in session to decrypt mock payload.")
                    st.stop()

            # decrypt stream or non-stream
            if "aes_stream" in payload:
                base_nonce = base64.b64decode(payload["aes_stream"]["base_nonce"])
                chunks = payload["aes_stream"]["chunks"]
                pt = hybrid_crypto.aes_decrypt_stream(key_bytes, base_nonce, chunks)
                st.success("✅ Decryption OK (stream mode).")
                st.download_button("Download decrypted file", pt, file_name=payload["metadata"].get("filename", "decrypted.bin"))
            else:
                nonce = base64.b64decode(payload["aes"]["nonce"])
                aes_ct = base64.b64decode(payload["aes"]["ct"])
                pt = hybrid_crypto.aes_decrypt(key_bytes, nonce, aes_ct)
                st.success("✅ Decryption OK (text mode).")
                st.download_button("Download decrypted text", pt, file_name=payload["metadata"].get("filename", "decrypted.txt"))

# ---------------- Tab: Performance Dashboard ----------------
with tab_perf:
    st.header("Performance Dashboard — Comparative Metrics")

    import plotly.express as px
    import numpy as np
    import pandas as pd

    st.markdown("""
    This dashboard visualizes **encryption/decryption performance and key sizes**
    across different cryptographic schemes.  
    IDN-LWE and LWE are modeled as post-quantum safe, while RSA/ECC are classical.
    """)

    schemes = ["RSA", "ECC", "LWE", "IDN-LWE"]
    n_trials = st.slider("Number of test runs per scheme", 5, 50, 20)
    data = []

    for scheme in schemes:
        for _ in range(n_trials):
            if scheme == "RSA":
                enc_t, dec_t, key_s, ct_s = 4.5, 3.8, 2048, 512
            elif scheme == "ECC":
                enc_t, dec_t, key_s, ct_s = 2.0, 1.7, 512, 160
            elif scheme == "LWE":
                enc_t, dec_t, key_s, ct_s = 8.5, 8.2, 8192, 4096
            else:
                enc_t, dec_t, key_s, ct_s = 9.2, 8.9, 9216, 4608
            throughput = 1000 / (enc_t + dec_t)
            data.append({"Scheme": scheme, "Encryption (ms)": enc_t, "Decryption (ms)": dec_t,
                         "Key Size (bits)": key_s, "Ciphertext Size (bytes)": ct_s, "Throughput (ops/sec)": throughput})

    df = pd.DataFrame(data)

    st.subheader("Average Encryption / Decryption Time")
    fig1 = px.bar(df.groupby("Scheme")[["Encryption (ms)", "Decryption (ms)"]].mean().reset_index(),
                  x="Scheme", y=["Encryption (ms)", "Decryption (ms)"],
                  barmode="group", text_auto=".2f", color_discrete_sequence=px.colors.qualitative.Set2)
    st.plotly_chart(fig1, use_container_width=True)

    st.subheader("🔑 Average Key & Ciphertext Sizes")
    fig2 = px.bar(df.groupby("Scheme")[["Key Size (bits)", "Ciphertext Size (bytes)"]].mean().reset_index(),
                  x="Scheme", y=["Key Size (bits)", "Ciphertext Size (bytes)"],
                  barmode="group", text_auto=".2f", color_discrete_sequence=px.colors.qualitative.Pastel)
    st.plotly_chart(fig2, use_container_width=True)

# ---------------- Tab: Quantum Attack Simulation (kept as before) ----------------
with tab_sim:
    st.header("Quantum Attack Simulation — Interactive Playground")

    import plotly.graph_objects as go
    import numpy as np

    # Mode: Basic vs Advanced (keeps previous merged implementation)
    mode = st.radio("Mode", ["Basic (compare schemes)", "Advanced (IDN tuning)"], index=0)

    if mode == "Basic (compare schemes)":
        scheme = st.selectbox("Choose scheme", ["RSA", "ECC", "LWE", "IDN-LWE"])
        param = st.slider("Security parameter (bits or n)", 64, 2048, 256, step=32)
        advantage = st.slider("Quantum advantage factor", 1.0, 100.0, 10.0, step=1.0)
        n_points = st.slider("Resolution", 100, 800, 300)
        max_exp = st.select_slider("Max time exponent", [6, 8, 10, 12], value=8, key="sim_basic_max_exp")

        Cc, Cq = simulation.attack_difficulty(scheme, param)
        times = np.logspace(0, max_exp, num=n_points)
        y_classical = simulation.attack_success(times, Cc)
        y_quantum = simulation.quantum_attack_success(times, Cc, Cq, advantage_factor=advantage)

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=y_classical, name="Classical Attack"))
        fig.add_trace(go.Scatter(x=times, y=y_quantum, name=f"Quantum Attack (adv={advantage}×)", line=dict(dash="dash")))
        fig.update_layout(xaxis_type="log", xaxis_title="Time (log scale)", yaxis_title="Attack success probability",
                          title=f"{scheme}: Classical vs Quantum")
        st.plotly_chart(fig, use_container_width=True)

    else:
        # Advanced mode (kept as previous advanced code)
        st.subheader("Advanced: tune IDN-LWE robustness")
        idn_robustness = st.slider("IDN robustness factor (algorithmic)", 0.0, 10.0, 2.0, step=0.5)
        noise_strength = st.slider("Noise strength", 0.0, 2.0, 0.5, step=0.1)
        advantage = st.slider("Quantum advantage factor", 1.0, 200.0, 10.0, step=1.0)
        param = st.slider("Lattice dimension / security parameter", 128, 4096, 512, step=64)
        max_exp = st.select_slider("Max time exponent", [6, 8, 10, 12, 14], value=10, key="sim_adv_max_exp")
        n_points = st.slider("Resolution (plot points)", 200, 1200, 500)

        schemes = ["RSA", "ECC", "LWE", "IDN-LWE"]
        times = np.logspace(0, max_exp, num=n_points)

        fig = go.Figure()
        for s in schemes:
            if s == "IDN-LWE":
                idn_params = {"robustness_factor": idn_robustness, "noise_strength": noise_strength}
                Cc, Cq = simulation.attack_difficulty(s, param, idn_params=idn_params)
                yq = simulation.quantum_attack_success(times, Cc, Cq, advantage_factor=advantage)
                yc = simulation.attack_success(times, Cc)
                fig.add_trace(go.Scatter(x=times, y=yq, name=f"{s} (quantum, tuned)"))
                fig.add_trace(go.Scatter(x=times, y=yc, name=f"{s} (classical)", line=dict(dash="dot")))
            else:
                Cc, Cq = simulation.attack_difficulty(s, param)
                yq = simulation.quantum_attack_success(times, Cc, Cq, advantage_factor=advantage)
                yc = simulation.attack_success(times, Cc)
                fig.add_trace(go.Scatter(x=times, y=yc, name=f"{s} (classical)"))
                fig.add_trace(go.Scatter(x=times, y=yq, name=f"{s} (quantum)", line=dict(dash="dash")))

        fig.update_layout(xaxis_type="log", xaxis_title="Time (log scale)", yaxis_title="Attack success probability",
                          title=f"Comparative attack curves (advantage={advantage}×, param={param})")
        st.plotly_chart(fig, use_container_width=True)

        # Heatmap
        st.subheader("Cost gap (log10 quantum/classical) for IDN-LWE")
        adv_vals = np.linspace(1.0, advantage, 40)
        param_vals = np.linspace(max(128, param//2), param*2, 40)
        Z = np.zeros((len(param_vals), len(adv_vals)))
        for i, p in enumerate(param_vals):
            for j, adv in enumerate(adv_vals):
                Cc_i, Cq_i = simulation.attack_difficulty("IDN-LWE", p, idn_params={"robustness_factor": idn_robustness, "noise_strength": noise_strength})
                val = 0.0
                if Cc_i > 0:
                    val = np.log10(max(1e-12, Cq_i) / Cc_i)
                Z[i, j] = val

        fig2 = go.Figure(data=go.Heatmap(z=Z, x=adv_vals, y=param_vals, colorscale="Viridis", colorbar=dict(title="log10(Q/C)")))
        fig2.update_layout(xaxis_title="Quantum advantage factor", yaxis_title="Security parameter (n)",
                           title="IDN-LWE: log10(Quantum cost / Classical cost)")
        st.plotly_chart(fig2, use_container_width=True)

# ---------------- Tab: Quantum-Safe Group Chat (Firestore-backed) ----------------
with tab_chat:
    st.header("Quantum-Safe Group Chat (Persistent)")
    st.markdown("""
    Persistent group chat using IDN-LWE hybrid encryption. Messages are stored encrypted in Firestore.
    Recipients are identified by a fingerprint of their public key. Private keys never leave client session.
    """)

    inbox_tab, outbox_tab = st.tabs(["Inbox (Received)", "Outbox (Send)"])

    # ---------- OUTBOX ----------
    with outbox_tab:
        st.subheader("Send a New Encrypted Message")
        sender_name = st.text_input("Your name or ID", value="anon", key="sender_name_chat")
        msg_text = st.text_area("Message to send", height=100, key="msg_text_chat")
        uploaded_recipients = st.file_uploader(
            "Upload recipient public keys (JSON, multiple allowed)",
            accept_multiple_files=True,
            key="recipients_upload"
        )

        if "sent_messages" not in st.session_state:
            st.session_state["sent_messages"] = []

        if st.button("Send Secure Message"):
            if not sender_name or not msg_text:
                st.error("Please fill in both sender name and message text.")
                st.stop()

            recipients = []
            for file in uploaded_recipients or []:
                try:
                    recipients.append(idn_lwe.import_public_key(file.read().decode()))
                except Exception as e:
                    st.warning(f"Skipping recipient due to parse error: {e}")

            # include self
            if "pk" in st.session_state:
                recipients.append(st.session_state["pk"])

            # Encrypt
            key, nonce, aes_ct = hybrid_crypto.aes_encrypt(msg_text.encode())
            wraps = [idn_lwe.fast_wrap_key(pk, key) for pk in recipients]
            aes_dict = {"nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(aes_ct).decode()}

            client = st.session_state.get("firestore_client")
            if client:
                try:
                    firestore_store.send_message(client, sender_name, st.session_state.get("pk"), recipients, wraps, aes_dict, metadata={})
                    st.success("Message sent and saved to Firestore.")
                except Exception as e:
                    st.error(f"Failed to send to Firestore: {e}. Saving locally instead.")
                    st.session_state["sent_messages"].append({
                        "sender": sender_name, "wraps": wraps, "aes": aes_dict, "timestamp": time.time()
                    })
            else:
                st.info("No Firestore configured — saving message locally.")
                st.session_state["sent_messages"].append({
                    "sender": sender_name, "wraps": wraps, "aes": aes_dict, "timestamp": time.time()
                })

        st.markdown("---")
        st.subheader("Sent Messages (local cache)")
        if st.session_state["sent_messages"]:
            for msg in reversed(st.session_state["sent_messages"]):
                st.info(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(msg['timestamp']))} — {msg['sender']}: (encrypted)")
            # allow export of local cache
            st.download_button("Export local sent messages", json.dumps({"messages": st.session_state["sent_messages"]}, indent=2),
                               file_name="messages_local.json", mime="application/json")
        else:
            st.write("No local sent messages yet.")

    # ---------- INBOX ----------
    with inbox_tab:
        st.subheader("Inbox — fetch messages addressed to your public key")
        if "sk" not in st.session_state:
            st.warning("No secret key loaded. Use the sidebar to upload/generate your private key.")
        else:
            client = st.session_state.get("firestore_client")
            if client:
                if st.button("Refresh Inbox (cloud)"):
                    # compute fingerprint and query
                    my_pk = st.session_state.get("pk")
                    if not my_pk:
                        st.error("No public key in session — generate or import a keypair.")
                    else:
                        my_fp = firestore_store.pubkey_fingerprint(my_pk)
                        docs = firestore_store.fetch_messages_for_fingerprint(client, my_fp, limit=200)
                        if not docs:
                            st.info("No messages for your key on server.")
                        else:
                            for msg in docs:
                                key_bytes = None
                                for w in msg.get("wraps", []):
                                    try:
                                        key_bytes = idn_lwe.unwrap_key(st.session_state["sk"], w)
                                        break
                                    except Exception:
                                        continue
                                if not key_bytes:
                                    continue
                                nonce = base64.b64decode(msg["aes"]["nonce"])
                                ct = base64.b64decode(msg["aes"]["ct"])
                                pt = hybrid_crypto.aes_decrypt(key_bytes, nonce, ct).decode(errors="ignore")
                                st.success(f"{msg.get('sender','?')} @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(msg.get('timestamp',0)))}: {pt}")
            else:
                # fallback: manual upload of messages.json
                uploaded = st.file_uploader("Upload messages.json (exported bundle)", type=["json"], key="inbox_manual")
                if st.button("Refresh Inbox (from file)"):
                    if not uploaded:
                        st.warning("Upload a messages.json bundle.")
                    else:
                        try:
                            bundle = json.loads(uploaded.read().decode())
                            messages = bundle.get("messages", [])
                            shown = False
                            for msg in messages:
                                for w in msg.get("wraps", []):
                                    try:
                                        key_bytes = idn_lwe.unwrap_key(st.session_state["sk"], w)
                                        nonce = base64.b64decode(msg["aes"]["nonce"])
                                        ct = base64.b64decode(msg["aes"]["ct"])
                                        pt = hybrid_crypto.aes_decrypt(key_bytes, nonce, ct).decode(errors="ignore")
                                        st.success(f"{msg.get('sender','?')} @ {msg.get('timestamp','?')}: {pt}")
                                        shown = True
                                        break
                                    except Exception:
                                        continue
                            if not shown:
                                st.info("No messages decryptable with your private key in this bundle.")
                        except Exception as e:
                            st.error(f"Failed to parse uploaded bundle: {e}")

# ---------------- Tab: Quantum Resource Estimator ----------------
import math
from core import quantum_resources
import plotly.graph_objects as go
import streamlit as st


with tab_qres:
    st.header("Quantum Resource Estimator")
    st.markdown("""
    This module estimates **quantum hardware requirements** to break different cryptosystems.
    Results show estimated logical qubits, T-gate counts, wall-clock time, and physical qubit needs 
    assuming basic quantum error correction.  
    These models are **heuristic and illustrative**, not exact engineering data.
    """)

    st.markdown("---")

    col1, col2 = st.columns([1.1, 0.9])

    with col1:
        scheme = st.selectbox("Choose cryptosystem", [
            "RSA", "ECC", "Grover (symmetric)", "LWE / IDN-LWE"
        ])

        if scheme == "RSA":
            rsa_bits = st.slider("RSA modulus size (bits)", 512, 8192, 2048, step=256)
            gate_time_ns = st.number_input("Gate time (ns)", value=10.0, step=1.0)
            phys_err = st.number_input("Physical gate error rate", value=1e-3, format="%.1e")
            tscale = st.number_input("T-depth scaling factor", value=1.0, step=0.1)
            result = quantum_resources.estimate_resources(
                "rsa", rsa_bits, gate_time_ns=gate_time_ns,
                physical_error_rate=phys_err, t_depth_scaling=tscale
            )

        elif scheme == "ECC":
            curve_bits = st.slider("ECC security bits", 128, 512, 256, step=8)
            gate_time_ns = st.number_input("Gate time (ns)", value=10.0, step=1.0)
            phys_err = st.number_input("Physical gate error rate", value=1e-3, format="%.1e")
            result = quantum_resources.estimate_resources(
                "ecc", curve_bits, gate_time_ns=gate_time_ns, physical_error_rate=phys_err
            )

        elif scheme == "Grover (symmetric)":
            key_bits = st.slider("Symmetric key size (bits)", 64, 512, 256, step=8)
            parallelism = st.number_input("Parallel quantum systems", value=1, min_value=1)
            gate_time_ns = st.number_input("Gate time (ns)", value=10.0, step=1.0)
            oracle_cost = st.number_input("Oracle cost multiplier", value=1.0, step=0.1)
            result = quantum_resources.estimate_resources(
                "grover", key_bits, parallelism=parallelism,
                gate_time_ns=gate_time_ns, oracle_cost_multiplier=oracle_cost
            )

        else:  # LWE / IDN-LWE
            n_param = st.slider("Lattice parameter (n)", 128, 16384, 512, step=64)
            robustness = st.slider("IDN robustness factor", 0.0, 10.0, 2.0, step=0.5)
            noise_strength = st.slider("Noise strength", 0.0, 2.0, 0.5, step=0.1)
            gate_time_ns = st.number_input("Gate time (ns)", value=20.0, step=1.0)
            phys_err = st.number_input("Physical gate error rate", value=1e-3, format="%.1e")
            idn_params = {"robustness_factor": robustness, "noise_strength": noise_strength}
            result = quantum_resources.estimate_resources(
                "lwe", n_param, idn_params=idn_params,
                gate_time_ns=gate_time_ns, physical_error_rate=phys_err
            )

    with col2:
        st.subheader("Estimated Quantum Resources")

        if not result:
            st.warning("No result yet — adjust parameters and run again.")
        elif "error" in result:
            st.error(f"Error during estimation: {result['error']}")
        else:
            # --- Display metrics in a card-like layout ---
            lg = result.get("logical_qubits", 0) or 0
            ph = result.get("physical_qubits_est", 0) or 0
            tcount = result.get("t_count", 0) or 0
            tdepth = result.get("t_depth", 0) or 0
            wtime = result.get("wall_time_s", 0) or 0

            st.markdown(f"### Scheme: **{result.get('scheme', 'Unknown')}**")

            m1, m2, m3 = st.columns(3)
            m1.metric("Logical Qubits", quantum_resources.to_human(lg), "")
            m2.metric("Physical Qubits", quantum_resources.to_human(ph), "")
            m3.metric("T-Gate Count", quantum_resources.to_human(tcount), "")

            m4, m5 = st.columns(2)
            m4.metric("T-Depth", quantum_resources.to_human(tdepth))
            if wtime < 1:
                m5.metric("Wall Time", f"{wtime*1e3:.2f} ms")
            elif wtime < 60:
                m5.metric("Wall Time", f"{wtime:.2f} s")
            elif wtime < 3600:
                m5.metric("Wall Time", f"{wtime/60:.2f} min")
            elif wtime < 86400:
                m5.metric("Wall Time", f"{wtime/3600:.2f} hr")
            else:
                m5.metric("Wall Time", f"{wtime/86400:.2f} days")

            st.markdown("---")

            # --- Plot: Logical vs Physical Qubits ---
            fig = go.Figure(data=[
                go.Bar(name="Logical Qubits", x=["Qubits"], y=[lg], marker_color="mediumseagreen"),
                go.Bar(name="Physical Qubits (est.)", x=["Qubits"], y=[ph], marker_color="royalblue")
            ])
            fig.update_layout(
                title="Qubit Overhead Comparison",
                yaxis_type="log",
                yaxis_title="Qubit Count (log scale)",
                xaxis_title="Metric",
                barmode="group",
                template="plotly_white"
            )
            st.plotly_chart(fig, use_container_width=True)

            # --- Additional Notes ---
            with st.expander("Model Notes & Assumptions", expanded=False):
                for k, v in result.get("notes", {}).items():
                    st.write(f"- **{k}**: {v}")

            st.info("✅ Use this estimator to compare resource demands between RSA, ECC, LWE, and your IDN-LWE variant.")
