import streamlit as st
import json
import base64
import os
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Load environment variables
load_dotenv()

# ---------- Page Config ----------
st.set_page_config(
    page_title="RIPS Microcredential Verifier",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ---------- Safe query parameter retrieval ----------
def get_query_param(key, default=None):
    """Works with both new (st.query_params) and old (st.experimental_get_query_params) Streamlit versions."""
    try:
        # New way (Streamlit >= 1.30.0)
        value = st.query_params.get(key, default)
    except AttributeError:
        params = st.experimental_get_query_params()
        if key in params:
            value = params[key][0]
        else:
            value = default
    if isinstance(value, list):
        return value[0] if value else default
    return value

# ---------- Custom CSS ----------
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        border-radius: 12px;
        margin-bottom: 2rem;
        color: white;
    }
    .main-header h1 {
        margin: 0;
        font-weight: 700;
        font-size: 2.5rem;
        letter-spacing: 1px;
    }
    .main-header p {
        margin: 0.25rem 0 0;
        opacity: 0.85;
        font-size: 1.1rem;
    }
    .cert-card {
        background: white;
        border-radius: 16px;
        padding: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.08);
        border: 1px solid #e8ecf1;
        margin: 1.5rem 0;
        transition: all 0.2s;
    }
    .cert-card .field {
        display: flex;
        justify-content: space-between;
        padding: 0.6rem 0;
        border-bottom: 1px solid #f0f2f6;
    }
    .cert-card .field:last-child {
        border-bottom: none;
    }
    .cert-card .label {
        font-weight: 600;
        color: #4a5568;
        letter-spacing: 0.3px;
    }
    .cert-card .value {
        color: #1a202c;
        font-weight: 500;
        word-break: break-word;
        text-align: right;
    }
    .badge-valid {
        background: #48bb78;
        color: white;
        padding: 0.25rem 0.8rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.9rem;
        display: inline-block;
    }
    .badge-invalid {
        background: #fc8181;
        color: white;
        padding: 0.25rem 0.8rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.9rem;
        display: inline-block;
    }
    .badge-revoked {
        background: #ed8936;
        color: white;
        padding: 0.25rem 0.8rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.9rem;
        display: inline-block;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #a0aec0;
        font-size: 0.9rem;
        border-top: 1px solid #edf2f7;
        padding-top: 1.5rem;
    }
    .stButton button {
        width: 100%;
        background: #2a5298;
        color: white;
        font-weight: 600;
        border-radius: 8px;
        padding: 0.6rem;
        border: none;
        transition: background 0.2s;
    }
    .stButton button:hover {
        background: #1e3c72;
        color: white;
    }
    .stTextInput input {
        border-radius: 8px;
        border: 1px solid #cbd5e0;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Supabase Setup ----------
SUPABASE_URL = st.secrets.get("SUPABASE_URL") or os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = st.secrets.get("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    st.error("⚠️ Supabase credentials not found. Please set them in secrets or .env.")
    st.stop()

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# ---------- Load Public Key ----------
@st.cache_resource
def load_public_key():
    try:
        with open("issuer_public_key.pem", "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        st.error("❌ Public key file 'issuer_public_key.pem' not found.")
        st.stop()

public_key = load_public_key()

# ---------- Header with Logo ----------
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    try:
        st.image("Logo.png", width=120)
    except FileNotFoundError:
        st.caption("(Logo not found)")

st.markdown("""
<div class="main-header">
    <h1>🔍 RIPS Microcredential Verifier</h1>
    <p>Verify the authenticity of your digital certificate</p>
</div>
""", unsafe_allow_html=True)

# ---------- Verification Logic ----------
payload = get_query_param("payload")
cert_id_param = get_query_param("cert_id")

if not payload and not cert_id_param:
    cert_id = st.text_input("Enter Certificate ID", placeholder="e.g., CERT-2024-001")
    verify_clicked = st.button("Verify Certificate")
else:
    cert_id = cert_id_param
    verify_clicked = True

if verify_clicked:
    try:
        if payload:
            # Decode the base64url payload (add padding if missing)
            decoded_bytes = base64.urlsafe_b64decode(payload + '==')
            data = json.loads(decoded_bytes)
            
            cert_data = data.get("d")
            signature_b64 = data.get("s")
            
            if not cert_data or not signature_b64:
                st.error("❌ Invalid payload: missing data or signature.")
                st.stop()
            
            # Decode signature and verify
            signature = base64.urlsafe_b64decode(signature_b64 + '==')
            data_to_verify = json.dumps(cert_data, sort_keys=True).encode('utf-8')
            
            sig_valid = False
            try:
                public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
                sig_valid = True
            except Exception:
                pass
            
            if not sig_valid:
                st.error("❌ **INVALID CERTIFICATE** – Signature verification failed. This certificate has been tampered with.")
                st.stop()
            
            # Extract cert_id from payload
            cert_id = cert_data.get("cert_id") or cert_data.get("id")
            if not cert_id:
                st.error("❌ Certificate ID not found in signed data.")
                st.stop()
        elif cert_id_param:
            cert_id = cert_id_param
        
        # Query Supabase using cert_id
        if cert_id:
            response = supabase.table("certificates").select("*").eq("cert_id", cert_id).execute()
            
            if not response.data:
                st.warning("⚠️ Certificate ID not found in the official registry.")
                if payload and cert_data:
                    st.info("The cryptographic signature is valid, but this certificate is not registered in our system.")
                st.stop()
            
            record = response.data[0]
            is_valid = record.get("is_valid", False)
            revoked_at = record.get("revoked_at")
            
            # --- Certificate is valid and not revoked ---
            if is_valid and not revoked_at:
                st.success("✅ **VALID & AUTHENTIC CERTIFICATE**")
                
                # Build display data (prefer signed payload if available)
                if payload and cert_data:
                    display_data = {
                        "cert_id": cert_data.get("cert_id") or record.get("cert_id"),
                        "name": cert_data.get("name") or record.get("name"),
                        "program": cert_data.get("program") or record.get("program"),
                        "issuer": cert_data.get("issuer") or record.get("issuer"),
                        "issued_at": cert_data.get("issued_at") or record.get("issued_at"),
                        "facilitators": cert_data.get("facilitators") or record.get("facilitators"),
                        "facilitator_name": cert_data.get("facilitator_name") or record.get("facilitator_name"),
                        "facilitator_email": cert_data.get("facilitator_email") or record.get("facilitator_email"),
                        "facilitator_contact": cert_data.get("facilitator_contact") or record.get("facilitator_contact"),
                        "office_contact": cert_data.get("office_contact") or record.get("office_contact"),
                    }
                else:
                    display_data = {
                        "cert_id": record.get("cert_id"),
                        "name": record.get("name"),
                        "program": record.get("program"),
                        "issuer": record.get("issuer"),
                        "issued_at": record.get("issued_at"),
                        "facilitators": record.get("facilitators"),
                        "facilitator_name": record.get("facilitator_name"),
                        "facilitator_email": record.get("facilitator_email"),
                        "facilitator_contact": record.get("facilitator_contact"),
                        "office_contact": record.get("office_contact"),
                    }
                
                # Render certificate card
                st.markdown("""
                <div class="cert-card">
                    <h3 style="margin-top:0; color:#2a5298;">📄 Certificate Details</h3>
                    <div style="margin: 1rem 0;">
                        <span class="badge-valid">✅ VALID</span>
                    </div>
                """, unsafe_allow_html=True)
                
                fields = [
                    ("Certificate ID", display_data.get("cert_id")),
                    ("Holder Name", display_data.get("name")),
                    ("Program / Course", display_data.get("program")),
                    ("Issuer", display_data.get("issuer")),
                    ("Issue Date", display_data.get("issued_at")),
                    ("Facilitators", display_data.get("facilitators")),
                    ("Focal Facilitator", display_data.get("facilitator_name")),
                    ("Facilitator Email", display_data.get("facilitator_email")),
                    ("Facilitator Contact", display_data.get("facilitator_contact")),
                    ("Office Contact", display_data.get("office_contact")),
                ]
                for label, value in fields:
                    if value:
                        st.markdown(f"""
                        <div class="field">
                            <span class="label">{label}</span>
                            <span class="value">{value}</span>
                        </div>
                        """, unsafe_allow_html=True)
                
                if payload:
                    st.markdown("""
                    <div style="margin-top:1rem; padding:0.5rem; background:#f0fff4; border-radius:8px; border-left:4px solid #48bb78;">
                        <span style="color:#276749;">🔒 Digitally signed and verified using ECDSA</span>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("</div>", unsafe_allow_html=True)
                st.balloons()
            
            # --- Certificate revoked ---
            elif revoked_at:
                st.error("❌ **CERTIFICATE REVOKED**")
                st.markdown(f"""
                <div class="cert-card" style="border-color:#fc8181;">
                    <p>This certificate was revoked on <strong>{revoked_at}</strong>.</p>
                    <p>Please contact the issuing authority for further information.</p>
                </div>
                """, unsafe_allow_html=True)
            
            # --- Certificate marked invalid ---
            else:
                st.warning("⚠️ **CERTIFICATE INVALID** – The certificate is marked as invalid in our system.")
        else:
            st.info("Please enter a Certificate ID or scan a QR code.")
    
    except Exception as e:
        st.error(f"❌ An error occurred: {str(e)}")

# ---------- Footer ----------
st.markdown("""
<div class="footer">
    🔒 Secure verification using ECDSA signatures + Supabase • Issued by RIPS
</div>
""", unsafe_allow_html=True)
