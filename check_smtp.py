import smtplib

s = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
s.starttls()
s.login("insightly.com@gmail.com", "reoj wezq gcbj gxwb")
s.quit()
