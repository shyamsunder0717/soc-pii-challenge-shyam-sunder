#!/usr/bin/env python
import csv
import json
import re
import sys

def chk_mobile(val):
    if not isinstance(val, str):
        val = str(val)
    t = re.sub(r'[\s\-\(\)\+]', '', val)
    return bool(re.match(r'^\d{10}$', t))
def chk_aadhar(val):
    if not isinstance(val, str):
        val = str(val)
    t = re.sub(r'[\s\-]', '', val)
    return bool(re.match(r'^\d{12}$', t))
def chk_passport(val):
    if not isinstance(val, str):
        return False
    return bool(re.match(r'^[A-Z]\d{7,8}$', val.upper()))
def chk_upi(val):
    if not isinstance(val, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$', val))
def chk_fullname(val):
    if not isinstance(val, str):
        return False
    p = val.strip().split()
    if len(p) < 2:
        return False
    for v in p:
        if not re.match(r'^[A-Za-z\.\-\']+$', v):
            return False
    return True
def chk_mail(val):
    if not isinstance(val, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val))
def chk_address(val):
    if not isinstance(val, str):
        return False
    val = val.strip()
    if len(val) < 10:
        return False
    has_pin = bool(re.search(r'\b\d{6}\b', val))
    parts = re.split(r'[,\n]', val)
    return has_pin and len(parts) >= 3
def hide_mobile(num):
    c = re.sub(r'[\s\-\(\)\+]', '', str(num))
    if len(c) == 10:
        return f"{c[:2]}XXXXXX{c[-2:]}"
    return "[REDACTED_PHONE]"
def hide_aadhar(num):
    c = re.sub(r'[\s\-]', '', str(num))
    if len(c) == 12:
        return f"{c[:2]}XXXXXXXX{c[-2:]}"
    return "[REDACTED_AADHAR]"
def hide_passport(pid):
    return f"{pid[0]}XXXXXXX" if len(pid) > 1 else "[REDACTED_PASSPORT]"
def hide_upi(uid):
    p = uid.split('@')
    if len(p) == 2:
        u, d = p
        return f"{u[:2]}XXX@{d}" if len(u) > 2 else f"XXX@{d}"
    return "[REDACTED_UPI]"
def hide_name(txt):
    ps = txt.strip().split()
    r = []
    for w in ps:
        r.append(f"{w[0]}{'X'*(len(w)-1)}" if len(w) > 1 else "X")
    return " ".join(r)
def hide_mail(mail):
    p = mail.split('@')
    if len(p) == 2:
        u, d = p
        return f"{u[:2]}XXX@{d}" if len(u) > 2 else f"XXX@{d}"
    return "[REDACTED_EMAIL]"
def hide_address(addr):
    r = re.sub(r'\d', 'X', addr)
    words = r.split()
    f = []
    for w in words:
        if len(w) > 3 and w.upper() not in ['ROAD', 'STREET', 'CITY', 'STATE']:
            f.append(f"{w[:2]}{'X'*(len(w)-2)}")
        else:
            f.append(w)
    return " ".join(f)
def detect_hide(data_str):
    try:
        obj = json.loads(data_str)
    except:
        return f'"{data_str}"', False
    pii = False
    new_obj = obj.copy()
    combi = []
    for k, v in obj.items():
        if v is None or v == "":
            continue
        s = str(v)
        if k in ['phone', 'contact'] and chk_mobile(s):
            new_obj[k] = hide_mobile(s)
            pii = True
        elif k == 'aadhar' and chk_aadhar(s):
            new_obj[k] = hide_aadhar(s)
            pii = True
        elif k == 'passport' and chk_passport(s):
            new_obj[k] = hide_passport(s)
            pii = True
        elif k == 'upi_id' and chk_upi(s):
            new_obj[k] = hide_upi(s)
            pii = True
        elif k == 'name' and chk_fullname(s):
            combi.append('name')
            new_obj[k] = hide_name(s)
        elif k == 'email' and chk_mail(s):
            combi.append('email')
            new_obj[k] = hide_mail(s)
        elif k == 'address' and chk_address(s):
            combi.append('address')
            new_obj[k] = hide_address(s)
        elif k in ['device_id', 'ip_address']:
            combi.append(k)
            new_obj[k] = "[REDACTED_ID]"
    if len(combi) >= 2:
        pii = True
    j = json.dumps(new_obj)
    esc = j.replace('"', '""')
    return f'"{esc}"', pii
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_shyam_sunder.py input.csv")
        sys.exit(1)
    inp = sys.argv[1]
    outp = "redacted_output_shyam_sunder.csv"
    try:
        with open(inp, 'r', encoding='utf-8') as f:
            rdr = csv.DictReader(f)
            cols = rdr.fieldnames
            print(f"Columns found: {cols}")
            cid = None
            dcol = None
            for c in cols:
                if 'id' in c.lower():
                    cid = c
                if 'data' in c.lower() or 'json' in c.lower():
                    dcol = c
            if not cid or not dcol:
                print("Error: Required columns not found")
                print("Available:", cols)
                sys.exit(1)
            print(f"Using '{cid}' as id and '{dcol}' as data")
            with open(outp, 'w', encoding='utf-8', newline='') as of:
                fn = ['record_id', 'redacted_data_json', 'is_pii']
                w = csv.DictWriter(of, fieldnames=fn)
                w.writeheader()
                print("\nrecord_id,redacted_data_json,is_pii")
                pc = 0
                pf = 0
                for r in rdr:
                    rid = r[cid]
                    dj = r[dcol]
                    rj, ip = detect_hide(dj)
                    w.writerow({'record_id': rid, 'redacted_data_json': rj, 'is_pii': ip})
                    print(f"{rid},{rj},{ip}")
                    pc += 1
                    if ip:
                        pf += 1
        print(f"\nProcessed {pc} rows, {pf} with PII.")
        print(f"Saved to {outp}")
    except FileNotFoundError:
        print(f"Error: File '{inp}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
if __name__ == "__main__":
    main()
