import re
import sqlparse

def analyze_sql(query):
    score = 0
    findings = []
    advice = []
    fixed_code = None  # New variable for the Auto-Fixer
    
    normalized_query = sqlparse.format(query, strip_comments=True, reindent=False).lower()
    parsed_statements = sqlparse.parse(normalized_query)
    
    # 1. Piggybacking / Stacked Queries
    if len(parsed_statements) > 1:
        score += 50
        findings.append("CRITICAL: Stacked Query detected (Multiple statements injected).")
        advice.append("FIX: Disable 'Multiple Statements' in your database connection string.")

    for statement in parsed_statements:
        raw_tokens = [token.value for token in statement.flatten()]
        token_string = " ".join(raw_tokens)
        
        # 2. Tautology (Auth Bypass)
        if re.search(r"or\s+(\d+)\s*=\s*\1|or\s+('|\")\w+\2\s*=\s*('|\")\w+\3", token_string):
            score += 40
            findings.append("HIGH: Tautology detected (e.g., 'OR 1=1'). Attempted auth bypass.")
            advice.append("FIX: Use Parameterized Queries (Prepared Statements).")
            
        # 3. Union Attack
        if "union" in raw_tokens and "select" in raw_tokens:
            score += 30
            findings.append("HIGH: UNION SELECT detected. Attempted data exfiltration.")
            advice.append("FIX: Validate input types and ensure proper role-based access control.")

        # 4. Dangerous Commands
        dangerous_keywords = ['drop', 'truncate', 'delete', 'xp_cmdshell', 'exec', 'sleep', 'benchmark']
        for word in dangerous_keywords:
            if word in raw_tokens:
                score += 40
                findings.append(f"CRITICAL: Destructive or System command '{word.upper()}' found.")
                advice.append(f"FIX: Enforce Principle of Least Privilege. Remove '{word.upper()}' permissions.")

        # 5. Schema Enumeration
        if "information_schema" in raw_tokens:
            score += 30
            findings.append("MEDIUM: Schema enumeration detected.")
            advice.append("FIX: Restrict user access to system catalog tables.")

    if score > 100:
        score = 100

    # --- THE AUTO-FIXER LOGIC ---
    if score > 0:
        if "select" in normalized_query:
            fixed_code = """# 🛡️ SECURE REMEDIATION (Python / SQLite3)
# Replace your dynamic string formatting with parameterized inputs:

cursor.execute("SELECT * FROM your_table WHERE your_column = ?", (user_input,))
secure_results = cursor.fetchall()"""
        elif "insert" in normalized_query:
            fixed_code = """# 🛡️ SECURE REMEDIATION (Python / SQLite3)
# Never trust user input. Use parameterized tuples:

cursor.execute("INSERT INTO your_table (col1, col2) VALUES (?, ?)", (val1, val2))
connection.commit()"""
        elif "update" in normalized_query:
            fixed_code = """# 🛡️ SECURE REMEDIATION (Python / SQLite3)
# Bind parameters safely to prevent payload execution:

cursor.execute("UPDATE your_table SET col1 = ? WHERE id = ?", (new_value, record_id))
connection.commit()"""
        else:
            fixed_code = """# 🛡️ SECURE REMEDIATION
# Ensure all user inputs are strictly parameterized before execution:
# cursor.execute("YOUR QUERY HERE WITH ?", (safe_parameters,))"""

    return score, findings, advice, fixed_code