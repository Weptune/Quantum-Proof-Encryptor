# app.py
import streamlit as st
import base64
from core import idn_lwe, hybrid_crypto, simulation

st.set_page_config(layout="wide", page_title="Quantum Secure Demo")

tab1, tab2 = st.tabs(["Encrypt / Decrypt", "Quantum Attack Simulation"])

# ------------------ Tab 1 ------------------
with tab1:
    st.header("Hybrid Encryption — IDN-LWE + AES-GCM (demo)")
    msg = st.text_area("Enter data to encrypt:", height=150)
    if st.button("Generate keys"):
        pk, sk = idn_lwe.keygen()
        st.session_state["pk"], st.session_state["sk"] = pk, sk
        st.success("Toy IDN-LWE keypair generated.")
    if st.button("Encrypt"):
        if "pk" not in st.session_state:
            st.error("Generate keys first.")
        else:
            key, nonce, ct = hybrid_crypto.aes_encrypt(msg.encode())
            wrapped = idn_lwe.wrap_key(st.session_state["pk"], key)
            payload = {
                "nonce": base64.b64encode(nonce).decode(),
                "aes_ct": base64.b64encode(ct).decode(),
                "wrapped_key": wrapped,
            }
            st.session_state["payload"] = payload
            st.json(payload)
            st.success("Encryption complete.")
    if st.button("Decrypt"):
        if "payload" not in st.session_state:
            st.error("No payload available.")
        else:
            data = st.session_state["payload"]
            sk = st.session_state["sk"]
            key = idn_lwe.unwrap_key(sk, data["wrapped_key"])
            pt = hybrid_crypto.aes_decrypt(
                key,
                base64.b64decode(data["nonce"]),
                base64.b64decode(data["aes_ct"]),
            )
            st.success("Decryption success:")
            st.text(pt.decode())

# ------------------ Tab 2 ------------------
with tab2:
    import plotly.graph_objects as go
    import numpy as np
    st.header("Quantum Attack Simulation")
    scheme = st.selectbox("Choose scheme", ["RSA", "ECC", "LWE", "IDN-LWE"])
    param = st.slider("Parameter (bits or n)", 64, 2048, 256, step=64)
    max_exp = st.select_slider("Max time exponent", [6,8,10,12], value=8)
    n_points = st.slider("Points", 100, 800, 300)
    Cc, Cq = simulation.map_costs(scheme, param)
    times = np.logspace(0, max_exp, n_points)
    y_class = simulation.attack_success(times, Cc)
    y_quant = simulation.attack_success(times, Cq)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=y_class, name="Classical"))
    fig.add_trace(go.Scatter(x=times, y=y_quant, name="Quantum", line=dict(dash="dash")))
    fig.update_layout(
        xaxis_type="log",
        xaxis_title="Time (log scale)",
        yaxis_title="Attack success probability",
        title=f"{scheme}: Classical vs Quantum Attack Simulation"
    )
    st.plotly_chart(fig, use_container_width=True)
