import streamlit as st
import pandas as pd
import time
import os
import tempfile
import re          
import random      
from datetime import datetime
from dotenv import load_dotenv
from fpdf import FPDF
from scanner import analyze_sql
import database as db
import google.generativeai as genai

# --- INITIALIZE DATABASES & SECURITY ---
db.init_db()
db.setup_dummy_db() # Keep this commented out so your database doesn't reset!

load_dotenv()
ADMIN_SECRET_KEY = os.getenv("ADMIN_KEY", "admin2024")
SESSION_TIMEOUT = 300 

# --- AI THREAT ANALYST ---
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('gemini-2.5-flash')
def generate_ai_report(query: str) -> str:
    prompt = f"Act as a Senior Cybersecurity Database Analyst. I intercepted this malicious SQL injection: {query}\nIn exactly 2 sentences, explain what this attack achieves."
    try:
        response = ai_model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"AI Analysis Error: {str(e)}" # This will print the exact technical error

# --- COMPLIANCE ENGINE: DATA MASKING ---
def mask_sensitive_data(df):
    masked_df = df.copy()
    for col in masked_df.columns:
        if masked_df[col].dtype == 'object':
            masked_df[col] = masked_df[col].apply(lambda x: re.sub(r'(^[\w\.-]+)@([\w\.-]+)', r'***@\2', str(x)) if isinstance(x, str) else x)
            masked_df[col] = masked_df[col].apply(lambda x: re.sub(r'\b\d{6,12}(\d{4})\b', r'XXXX-XXXX-\1', str(x)) if isinstance(x, str) else x)
    return masked_df

# --- PROCESSING ENGINE (WITH HONEYPOT LOGIC) ---
def process_query_with_honeypot(query):
    HONEYPOT_TABLE = "admin_passwords_backup"
    if HONEYPOT_TABLE in query.lower():
        score = 100
        status = "HONEYPOT BREACH"
        findings = [
            "🚨 CRITICAL TRAP TRIGGERED: Unauthorized access to hidden honeypot table.", 
            "Attacker is attempting to enumerate sensitive backup credentials.",
            "Source IP logged for automatic network ban."
        ]
        advice = ["Initiate Incident Response Plan.", "Block Attacker IP at the WAF level immediately."]
        fixed_code = "-- ACCESS DENIED. HONEYPOT TRAP ACTIVATED."
        return score, status, findings, advice, fixed_code
        
    score, findings, advice, fixed_code = analyze_sql(query)
    if score == 0: status = "SECURE"
    elif score < 50: status = "WARNING"
    else: status = "CRITICAL"
    return score, status, findings, advice, fixed_code

st.set_page_config(page_title="Ethical SQL Auditor", page_icon="☢️", layout="wide", initial_sidebar_state="expanded")

# --- DYNAMIC DARK CSS ---
def local_css():
    st.markdown("""
    <style>
        .stApp { background: radial-gradient(circle at 50% 0%, #1a1a2e 0%, #0f0c29 50%, #000000 100%); color: #a9b1d6; }
        h1, h2, h3, h4, h5 { color: #ffffff !important; font-family: 'Segoe UI', sans-serif; letter-spacing: 1px; }
        @keyframes pulse-border { 0% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(255, 0, 0, 0); } 100% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0); } }
        .dynamic-card { background: rgba(10, 10, 15, 0.8); backdrop-filter: blur(20px); border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1); padding: 30px; margin-bottom: 20px; transition: all 0.3s ease; }
        .stTextInput input, .stTextArea textarea { background-color: #050505 !important; color: #00ff88 !important; border: 1px solid #333 !important; font-family: 'Courier New', monospace; }
        .stButton button { background-color: transparent !important; color: #00ff88 !important; border: 1px solid #00ff88 !important; border-radius: 4px; text-transform: uppercase; letter-spacing: 2px; }
        .stButton button:hover { background-color: #00ff88 !important; color: #000 !important; box-shadow: 0 0 15px #00ff88; }
        .terminal-safe { border-left: 4px solid #00ff88; background: #050505; padding: 15px; color: #00ff88; font-family: monospace; }
        .terminal-warn { border-left: 4px solid #ffb86c; background: #050505; padding: 15px; color: #ffb86c; font-family: monospace; }
        .terminal-crit { border-left: 4px solid #ff5555; background: #050505; padding: 15px; color: #ff5555; font-family: monospace; }
        .terminal-honeypot { border-left: 4px solid #ff0000; background: #1a0000; padding: 15px; color: #ff0000; font-family: monospace; animation: pulse-border 1.5s infinite; }
    </style>
    """, unsafe_allow_html=True)
local_css()

# --- STATE INITIALIZATION ---
if 'logged_in' not in st.session_state: st.session_state['logged_in'] = False
if 'history' not in st.session_state: st.session_state['history'] = []
if 'last_active' not in st.session_state: st.session_state['last_active'] = time.time()
if 'ctf_score' not in st.session_state: st.session_state['ctf_score'] = 0

def generate_pdf_report(dataframe):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Ethical SQL Auditor - Threat Report", ln=True, align='C')
    pdf.set_font("Arial", 'I', 10)
    for index, row in dataframe.iterrows():
        safe_query = str(row.get('Query', 'N/A')).encode('latin-1', 'replace').decode('latin-1')
        pdf.cell(0, 8, f"[{row.get('Time', '')}] Risk: {row.get('Risk', '0')} | Type: {row.get('Type', 'Manual')}", ln=True)
        pdf.set_font("Courier", '', 9)
        pdf.multi_cell(0, 6, f"Query: {safe_query}")
        pdf.cell(0, 0, "-"*80, ln=True)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        pdf.output(tmp.name)
        with open(tmp.name, "rb") as f: return f.read()

def auth_page():
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.markdown('<div class="dynamic-card" style="text-align: center;"><h2>SYSTEM TERMINAL</h2><br>', unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["[ AUTHENTICATE ]", "[ INITIALIZE ]"])
        
        with tab1:
            u = st.text_input("USER_ID", key="login_u")
            p = st.text_input("PASSKEY", type="password", key="login_p")
            if st.button(">> CONNECT <<", use_container_width=True):
                role = db.check_login(u, p)
                if role:
                    st.session_state.update({'logged_in': True, 'username': u, 'user_role': role}); st.rerun()
                else: st.error("ACCESS DENIED")
                
        with tab2:
            nu = st.text_input("NEW_ID", key="reg_u")
            np = st.text_input("NEW_KEY", type="password", key="reg_p")
            ak = st.text_input("ADMIN_TOKEN (Optional)", type="password", key="reg_ak")
            if st.button(">> REGISTER <<", use_container_width=True):
                if not nu or not np:
                    st.warning("User ID and Passkey are required.")
                else:
                    role = "Admin" if ak == ADMIN_SECRET_KEY else "User"
                    if db.create_user(nu, np, role): 
                        st.success(f"UNIT CREATED: {role}. Logging in...")
                        time.sleep(1)
                        st.session_state.update({'logged_in': True, 'username': nu, 'user_role': role})
                        st.rerun()
                    else: 
                        st.error("ID CONFLICT: Username already exists.")
                        
        st.markdown('</div>', unsafe_allow_html=True)

def main_app():
    if time.time() - st.session_state['last_active'] > SESSION_TIMEOUT: st.session_state['logged_in'] = False; st.rerun()
    st.session_state['last_active'] = time.time()

    with st.sidebar:
        st.markdown(f"### 🛡️ {st.session_state.get('username', 'Unknown')}")
        st.caption(f"Clearance: {st.session_state.get('user_role', 'Unknown')}")
        if st.button(">> TERMINATE SESSION <<", use_container_width=True): st.session_state['logged_in'] = False; st.rerun()

    st.title("ETHICAL SQL AUDITOR")
    st.markdown("---")
    col_scan, col_res = st.columns([2, 1.2])
    
    with col_scan:
        st.markdown('<div class="dynamic-card">', unsafe_allow_html=True)
        st.subheader("LIVE VECTOR ANALYSIS")
        scan_tab1, scan_tab2, scan_tab3 = st.tabs(["[ MANUAL INPUT ]", "[ BATCH UPLOAD ]", "[ CYBER RANGE ]"])
        
        with scan_tab1:
            q = st.text_area("SQL Data Stream:", height=120, placeholder="Try injecting: SELECT * FROM admin_passwords_backup;")
            if st.button(">> EXECUTE SCAN <<", key="manual_scan", use_container_width=True):
                if q:
                    score, status, findings, advice, fixed_code = process_query_with_honeypot(q)
                    display_results(score, status, findings, advice, fixed_code, q, "Manual")
                    st.markdown("---")
                    st.subheader("🛡️ WAF Execution Engine")
                    
                    if status == "SECURE":
                        st.success("✅ Firewall Passed: Executing Query...")
                        # Ensure db.execute_safe_query is defined in database.py
                        if hasattr(db, 'execute_safe_query'):
                            result_df, error = db.execute_safe_query(q)
                            if error: st.warning(f"Syntax Error: {error}")
                            elif result_df is not None and not result_df.empty: 
                                secure_df = mask_sensitive_data(result_df)
                                st.success("🔒 Compliance Engine Active: Sensitive data masked.")
                                st.dataframe(secure_df, use_container_width=True)
                            else: st.info("Query executed successfully, no data returned.")
                        else:
                            st.info("Query safe, but database execution is disabled.")
                    elif status == "HONEYPOT BREACH":
                        st.error("💀 FIREWALL HARD-LOCK: Honeypot Triggered. Connection Terminated.")
                    else:
                        st.error("🚨 FIREWALL BLOCKED: Malicious payload dropped. Database protected.")
                else: st.warning("Empty data stream.")
                    
        with scan_tab2:
            st.write("Upload a `.sql` or `.txt` file containing multiple queries.")
            uploaded_file = st.file_uploader("Select Payload File", type=["sql", "txt"])
            
            if uploaded_file is not None:
                content = uploaded_file.getvalue().decode("utf-8")
                
                if st.button(">> EXECUTE BATCH SCAN <<", use_container_width=True):
                    with st.spinner("Processing Batch File..."):
                        queries = [q.strip() for q in content.split(";") if q.strip()]
                        for query in queries:
                            score, status, findings, advice, fixed_code = process_query_with_honeypot(query)
                            lat = 13.0827 if score == 0 else random.uniform(-60.0, 60.0) 
                            lon = 80.2707 if score == 0 else random.uniform(-150.0, 150.0)
                            st.session_state['history'].insert(0, {"Time": datetime.now().strftime("%H:%M:%S"), "User": st.session_state.get('username', 'Unknown'), "Risk": score, "Type": "Bulk", "Query": query, "lat": lat, "lon": lon})
                        st.success(f"Batch Processing Complete! {len(queries)} vectors scanned.")

        with scan_tab3:
            st.markdown("### 🎯 Defend The Flag: Training Range")
            st.code("# Vulnerable Python Backend\nuser_input = get_user_input()\nquery = f\"SELECT * FROM admins WHERE username = 'admin' AND password = '{user_input}'\"\ncursor.execute(query)", language="python")
            ctf_input = st.text_input("Enter your payload (e.g., ' OR 1=1 -- ):")
            
            if st.button(">> LAUNCH CYBER ATTACK <<", use_container_width=True):
                if ctf_input:
                    constructed_query = f"SELECT * FROM admins WHERE username = 'admin' AND password = '{ctf_input}'"
                    st.code(constructed_query, language="sql")
                    score, status, findings, advice, fixed_code = process_query_with_honeypot(constructed_query)
                    
                    if score > 0:
                        st.error("🛡️ MISSION FAILED: The Sentinel Shield caught your attack!")
                        st.session_state['ctf_score'] += 10
                        st.success(f"XP Gained! Training Score: {st.session_state['ctf_score']}")
                        with st.spinner("🤖 AI Analyst decoding your attack..."):
                            ai_report = generate_ai_report(constructed_query)
                        st.info(f"**🤖 AI Analyst:** {ai_report}")
                    else:
                        st.success("💀 CRITICAL BREACH: You bypassed the scanner!")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_res:
        st.markdown('<div class="dynamic-card">', unsafe_allow_html=True)
        st.subheader("TELEMETRY")
        if st.session_state['history']:
            df = pd.DataFrame(st.session_state['history'])
            st.markdown("##### 🌍 Global Threat Radar")
            st.map(df[['lat', 'lon']], color="#ff5555", zoom=1)
            st.line_chart(df['Risk'].head(15)[::-1], color="#00ff88")
            st.dataframe(df[['Time', 'Risk', 'Type']], use_container_width=True, height=200)
            
            if st.session_state.get('user_role') == "Admin":
                st.markdown("##### 📥 Export Reports")
                dl_col1, dl_col2 = st.columns(2)
                with dl_col1: st.download_button("💾 Get CSV", data=df.to_csv(index=False).encode('utf-8'), file_name="audit_log.csv", mime="text/csv", use_container_width=True)
                with dl_col2: st.download_button("📄 Get PDF", data=generate_pdf_report(df), file_name="threat_report.pdf", mime="application/pdf", use_container_width=True)
        else: st.caption("Awaiting telemetry data...")
        st.markdown('</div>', unsafe_allow_html=True)

def display_results(score, status, findings, advice, fixed_code, query, scan_type):
    if status == "HONEYPOT BREACH" or score == 100:
        st.markdown('<div class="terminal-honeypot">>> 🚨 STATUS: HONEYPOT BREACH (RISK 100) 🚨 <<</div>', unsafe_allow_html=True)
        st.error("💀 ACTIVE DECEPTION TRIGGERED: Attacker has fallen into the Honeypot trap. IP Ban initiated.")
    elif score == 0: st.markdown('<div class="terminal-safe">>> STATUS: SYSTEM SECURE (RISK 0)</div>', unsafe_allow_html=True)
    elif score < 50: st.markdown(f'<div class="terminal-warn">>> STATUS: WARNING (RISK {score})</div>', unsafe_allow_html=True)
    else: st.markdown(f'<div class="terminal-crit">>> STATUS: CRITICAL THREAT (RISK {score})</div>', unsafe_allow_html=True)
    
    if score > 0:
        with st.spinner("🤖 AI Analyst is generating a forensic report..."):
            ai_report = generate_ai_report(query)
        st.info(f"**🤖 Gemini AI Threat Analysis:**\n{ai_report}")
    
    if findings:
        for f in findings: st.error(f"🚩 {f}")
    if advice:
        for a in advice: st.info(f"🛡️ {a}")
    if fixed_code:
        st.markdown("#### 🛠️ Code Auto-Fixer:")
        st.code(fixed_code, language="python")
        
    lat = 13.0827 if score == 0 else random.uniform(-60.0, 60.0) 
    lon = 80.2707 if score == 0 else random.uniform(-150.0, 150.0)
    st.session_state['history'].insert(0, {"Time": datetime.now().strftime("%H:%M:%S"), "User": st.session_state.get('username', 'Unknown'), "Risk": score, "Type": scan_type, "Query": query, "lat": lat, "lon": lon})

if st.session_state['logged_in']: main_app()

else: auth_page()









