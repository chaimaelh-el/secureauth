import smtplib

# Test port 465
try:
    s = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=5)
    s.quit()
    print("Port 465 : OK")
except Exception as e:
    print(f"Port 465 : BLOQUÉ - {e}")

# Test port 587
try:
    s = smtplib.SMTP("smtp.gmail.com", 587, timeout=5)
    s.starttls()
    s.quit()
    print("Port 587 : OK")
except Exception as e:
    print(f"Port 587 : BLOQUÉ - {e}")