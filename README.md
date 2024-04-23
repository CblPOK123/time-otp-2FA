# time-otp-2FA
2FA проверочный код/двухэтапный инструмент  (аналог Google Authenticator) или Authenticator на python 

вообще это portable версия pyotp(https://pypi.org/project/pyotp/) 

Вот пример: 
from time_otp_2FA import timeotp
print(timeotp("B7S7GYYZWRHXIDAPFBMGOO5QU4WEKVD4"))

Без скрипта :
import calendar, datetime, time, base64, hashlib, hmac

def timeotp(secret):
 for_time = datetime.datetime.now()
 if for_time.tzinfo:
  now = int(calendar.timegm(for_time.utctimetuple()) / 30)
 else:
  now = int(time.mktime(for_time.timetuple()) / 30)

 missing_padding = len(secret) % 8
 if missing_padding != 0:
    secret += "=" * (8 - missing_padding)

 result = bytearray()
 while now != 0:
    result.append(now & 0xFF)
    now >>= 8

 hasher = hmac.new(base64.b32decode(secret, casefold=True), bytes(bytearray(reversed(result)).rjust(8, b"\0")), hashlib.sha1)
 hmac_hash = bytearray(hasher.digest())
 offset = hmac_hash[-1] & 0xF
 code = (
    (hmac_hash[offset] & 0x7F) << 24
    | (hmac_hash[offset + 1] & 0xFF) << 16
    | (hmac_hash[offset + 2] & 0xFF) << 8
    | (hmac_hash[offset + 3] & 0xFF)
 )
 str_code = str(10_000_000_000 + (code % 10**6))
 return str_code[-6 :]

print(timeotp("B7S7GYYZWRHXIDAPFBMGOO5QU4WEKVD4"))
