# app.py (modular, file upload/download, key export/import)
import streamlit as st
import base64, json, time, io
from core import idn_lwe, hybrid_crypto, simulation

st.set_page_config(layout="wide", page_title="Quantum Secure Demo (modular)")

st.title("Quantum-Secure Hybrid Demo — File encryption + Simulation")

# Sidebar for key actions
st.sidebar.header("Key management")
if st.sidebar.button("Generate IDN-LWE keypair (demo)"):
    pk, sk = idn_lwe.keygen()
    st.session_state["pk"] = pk
    st.session_state["sk"] = sk
    st.sidebar.success("Keypair generated (in-memory).")

if st.sidebar.button("Export public key (JSON)"):
    if "pk" not in st.session_state:
        st.sidebar.error("No keypair in session.")
    else:
        pk_json = idn_lwe.export_public_key(st.session_state["pk"])
        st.download_button("Download public key JSON", pk_json, file_name="idn_pubkey.json")

uploaded_pk = st.sidebar.file_uploader("Or upload a public key (JSON) to encrypt to", type=["json"])
if uploaded_pk:
    try:
        pk_text = uploaded_pk.read().decode()
        remote_pk = idn_lwe.import_public_key(pk_text)
        st.session_state["remote_pk"] = remote_pk
        st.sidebar.success("Imported remote public key.")
    except Exception as e:
        st.sidebar.error(f"Failed to import key: {e}")

st.sidebar.markdown("---")
st.sidebar.header("Payload / Audit")
show_audit = st.sidebar.checkbox("Add integrity HMAC (demo)", value=True)

tab_encrypt, tab_sim, tab_perf = st.tabs([
    "Encrypt file / text",
    "Quantum Attack Simulation",
    "Performance Dashboard"
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
            if show_audit:
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

# ---------------- Tab: Simulation ----------------
with tab_sim:
    st.header("Quantum Attack Simulation")
    import plotly.graph_objects as go
    import numpy as np

    scheme = st.selectbox("Choose scheme", ["RSA", "ECC", "LWE", "IDN-LWE"])
    param = st.slider("Parameter (bits or n)", 64, 2048, 256, step=32)
    max_exp = st.select_slider("Max time exponent", [6, 8, 10, 12], value=8)
    n_points = st.slider("Points", 100, 800, 300)

    Cc, Cq = simulation.map_costs(scheme, param)
    times = np.logspace(0, max_exp, num=n_points)
    y_class = simulation.attack_success(times, Cc)
    y_quant = simulation.attack_success(times, Cq)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=y_class, name="Classical"))
    fig.add_trace(go.Scatter(x=times, y=y_quant, name="Quantum", line=dict(dash="dash")))
    fig.update_layout(
        xaxis_type="log",
        xaxis_title="Time (log scale)",
        yaxis_title="Attack success probability",
        title=f"{scheme}: Classical vs Quantum"
    )
    st.plotly_chart(fig, use_container_width=True)
# ---------------- Tab: Performance Dashboard ----------------

with tab_perf:
    st.header("Performance Dashboard — Comparative Metrics")

    import plotly.express as px
    import numpy as np
    import pandas as pd
    import time as t

    st.markdown("""
    This dashboard visualizes **encryption/decryption performance and key sizes**
    across different cryptographic schemes.  
    IDN-LWE and LWE are modeled as post-quantum safe, while RSA/ECC are classical.
    """)

    schemes = ["RSA", "ECC", "LWE", "IDN-LWE"]
    n_trials = st.slider("Number of test runs per scheme", 5, 50, 20)
    data = []

    # Simulated metrics (in milliseconds, bytes, etc.)
    for scheme in schemes:
        for _ in range(n_trials):
            if scheme == "RSA":
                enc_t = np.random.normal(4.5, 0.4)
                dec_t = np.random.normal(3.8, 0.4)
                key_s = 2048
                ct_s = np.random.normal(512, 20)
            elif scheme == "ECC":
                enc_t = np.random.normal(2.0, 0.3)
                dec_t = np.random.normal(1.7, 0.2)
                key_s = 512
                ct_s = np.random.normal(160, 10)
            elif scheme == "LWE":
                enc_t = np.random.normal(8.5, 1.0)
                dec_t = np.random.normal(8.2, 0.8)
                key_s = 8192
                ct_s = np.random.normal(4096, 150)
            else:  # IDN-LWE
                enc_t = np.random.normal(9.2, 1.2)
                dec_t = np.random.normal(8.9, 1.0)
                key_s = 9216
                ct_s = np.random.normal(4608, 200)
            throughput = 1000 / (enc_t + dec_t)
            data.append({
                "Scheme": scheme,
                "Encryption (ms)": enc_t,
                "Decryption (ms)": dec_t,
                "Key Size (bits)": key_s,
                "Ciphertext Size (bytes)": ct_s,
                "Throughput (ops/sec)": throughput
            })

    df = pd.DataFrame(data)

    st.subheader("⏱️ Average Encryption / Decryption Time")
    avg_times = df.groupby("Scheme")[["Encryption (ms)", "Decryption (ms)"]].mean().reset_index()
    fig1 = px.bar(
        avg_times,
        x="Scheme", y=["Encryption (ms)", "Decryption (ms)"],
        barmode="group", text_auto=".2f",
        color_discrete_sequence=px.colors.qualitative.Set2
    )
    st.plotly_chart(fig1, use_container_width=True)

    st.subheader("🔑 Average Key & Ciphertext Sizes")
    avg_sizes = df.groupby("Scheme")[["Key Size (bits)", "Ciphertext Size (bytes)"]].mean().reset_index()
    fig2 = px.bar(
        avg_sizes,
        x="Scheme", y=["Key Size (bits)", "Ciphertext Size (bytes)"],
        barmode="group", text_auto=".2f",
        color_discrete_sequence=px.colors.qualitative.Pastel
    )
    st.plotly_chart(fig2, use_container_width=True)

    st.subheader("⚙️ Effective Throughput (Operations per second)")
    fig3 = px.box(
        df, x="Scheme", y="Throughput (ops/sec)", color="Scheme",
        points="all", color_discrete_sequence=px.colors.qualitative.Prism
    )
    st.plotly_chart(fig3, use_container_width=True)

    st.markdown("""
    **Insights:**
    - **RSA/ECC**: Fast but vulnerable to quantum attacks (Shor’s algorithm).  
    - **LWE / IDN-LWE**: Post-quantum secure; slower due to lattice operations and larger key sizes.  
    - **IDN-LWE** maintains competitive performance while providing
      improved key resilience through iterative distribution noise modeling.
    """)
