import streamlit as st
import json
import base64
from supabase import create_client, Client
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# ---------- Page Config ----------
st.set_page_config(
    page_title="RIPS Microcredential Verifier",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ---------- Safe query parameter retrieval ----------
def get_query_param(key, default=None):
    """Safely get query parameter (works across Streamlit versions)"""
    try:
        # Modern Streamlit (1.30+)
        params = st.query_params
        return params.get(key, default)
    except Exception:
        # Fallback for older versions
        try:
            params = st.experimental_get_query_params()
            return params.get(key, [default])[0] if key in params else default
        except:
            return default

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
    .main-header h1 { margin: 0; font-weight: 700; font-size: 2.5rem; }
    .main-header p { margin: 0.25rem 0 0; opacity: 0.9; }
    .cert-card {
        background: white;
        border-radius: 16px;
        padding: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.08);
        border: 1px solid #e8ecf1;
        margin: 1.5rem 0;
    }
    .field {
        display: flex;
        justify-content: space-between;
        padding: 0.75rem 0;
        border-bottom: 1px solid #f0f2f6;
    }
    .field:last-child { border-bottom: none; }
    .label { font-weight: 600; color: #4a5568; }
    .value { color: #1a202c; font-weight: 500; text-align: right; word-break: break-word; }
    .badge-valid {
        background: #48bb78; color: white; padding: 0.35rem 1rem;
        border-radius: 9999px; font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Supabase Setup ----------
SUPABASE_URL = st.secrets.get("SUPABASE_URL") or st.secrets.get("SUPABASE", {}).get("URL")
SUPABASE_ANON_KEY = st.secrets.get("SUPABASE_ANON_KEY") or st.secrets.get("SUPABASE", {}).get("ANON_KEY")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    st.error("⚠️ Supabase credentials not configured. Please add them in Streamlit Secrets.")
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
    except Exception as e:
        st.error(f"Error loading public key: {e}")
        st.stop()

public_key = load_public_key()

# ---------- Header ----------
col1, col2, col3 = st.columns([1, 4, 1])
with col2:
    st.markdown("""
    <div class="main-header">
        <h1>🔍 RIPS Microcredential Verifier</h1>
        <p>Verify the authenticity of your digital certificate</p>
    </div>
    """, unsafe_allow_html=True)

# ---------- Verification ----------
payload = get_query_param("payload")

if payload:
    verify_clicked = True
    manual_id = None
else:
    manual_id = st.text_input("Enter Certificate ID", placeholder="e.g., 9F9FB62C")
    verify_clicked = st.button("Verify Certificate", type="primary")

if verify_clicked:
    try:
        cert_data = None
        if payload:
            # Decode QR payload
            decoded_bytes = base64.urlsafe_b64decode(payload + '==')
            data = json.loads(decoded_bytes)
            cert_data = data.get("d")
            signature_b64 = data.get("s")

            if not cert_data or not signature_b64:
                st.error("Invalid payload")
                st.stop()

            # Verify signature
            signature = base64.urlsafe_b64decode(signature_b64 + '==')
            data_to_verify = json.dumps(cert_data, sort_keys=True).encode('utf-8')

            try:
                public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
            except:
                st.error("❌ **INVALID CERTIFICATE** – Signature verification failed.")
                st.stop()

            cert_id = cert_data.get("id") or cert_data.get("cert_id")
        else:
            cert_id = manual_id

        if not cert_id:
            st.warning("Please provide a Certificate ID or scan QR code.")
            st.stop()

        # Query Supabase
        response = supabase.table("certificates").select("*").eq("cert_id", cert_id).execute()
        
        if not response.data:
            st.warning("⚠️ Certificate not found in registry.")
            st.stop()

        record = response.data[0]
        is_valid = record.get("is_valid", False)
        revoked_at = record.get("revoked_at")

        if is_valid and not revoked_at:
            st.success("✅ **VALID & AUTHENTIC CERTIFICATE**")
            st.balloons()

            # Display card
            st.markdown('<div class="cert-card">', unsafe_allow_html=True)
            st.markdown('<span class="badge-valid">✓ VERIFIED</span>', unsafe_allow_html=True)

            fields = [
                ("Certificate ID", cert_data.get("id") if cert_data else record.get("cert_id")),
                ("Holder Name", cert_data.get("name") if cert_data else record.get("name")),
                ("Program", cert_data.get("program") if cert_data else record.get("program")),
                ("Issuer", cert_data.get("issuer") if cert_data else record.get("issuer")),
                ("Issued On", cert_data.get("issued_at") if cert_data else record.get("issued_at")),
            ]

            for label, value in fields:
                if value:
                    st.markdown(f"""
                    <div class="field">
                        <span class="label">{label}</span>
                        <span class="value">{value}</span>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown('</div>', unsafe_allow_html=True)

        elif revoked_at:
            st.error("❌ CERTIFICATE HAS BEEN REVOKED")
        else:
            st.warning("⚠️ This certificate is marked as invalid.")

    except Exception as e:
        st.error(f"❌ Error during verification: {str(e)}")

# Footer
st.markdown("---")
st.markdown("**Securely verified using ECDSA digital signatures + Supabase**")
