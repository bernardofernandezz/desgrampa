"""Aparelho falso: responde comandos do `adb shell` com saídas gravadas."""

from desgrampa.adb import AdbError

GETPROP = """\
[ro.product.manufacturer]: [samsung]
[ro.product.model]: [SM-A515F]
[ro.build.version.release]: [13]
[ro.build.version.sdk]: [33]
[ro.build.version.security_patch]: [{patch}]
[ro.build.tags]: [release-keys]
[ro.build.type]: [user]
[ro.boot.verifiedbootstate]: [green]
[ro.boot.flash.locked]: [1]
[ro.debuggable]: [0]
[gsm.sim.operator.numeric]: [72410]
[gsm.operator.numeric]: [{network}]
[gsm.operator.isroaming]: [false]
[gsm.sim.operator.alpha]: [VIVO]
[gsm.operator.alpha]: [VIVO]
"""

PM_LIST = """\
package:/system/priv-app/Settings/Settings.apk=com.android.settings  installer=null uid:1000
package:/data/app/~~aGVsbG8=/com.whatsapp-x1Y2==/base.apk=com.whatsapp  installer=com.android.vending uid:10150
"""

PM_THIRD = "package:com.whatsapp\n"

DUMPSYS_PACKAGE = """\
Packages:
  Package [com.android.settings] (a1b2c3):
    userId=1000
    sharedUser=SharedUserSetting{abc android.uid.system/1000}
    codePath=/system/priv-app/Settings
    flags=[ SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA ]
    firstInstallTime=2008-12-31 21:00:00
    requested permissions:
      android.permission.WRITE_SETTINGS
    install permissions:
      android.permission.WRITE_SETTINGS: granted=true
  Package [com.whatsapp] (d4e5f6):
    userId=10150
    codePath=/data/app/~~aGVsbG8=/com.whatsapp-x1Y2==
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    versionName=2.24.1
    firstInstallTime=2020-01-01 10:00:00
    lastUpdateTime=2024-01-01 10:00:00
    installerPackageName=com.android.vending
    requested permissions:
      android.permission.RECORD_AUDIO
      android.permission.READ_CONTACTS
      android.permission.READ_SMS, restricted=true
      android.permission.RECEIVE_BOOT_COMPLETED
    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
    User 0: ceDataInode=123 installed=true hidden=false suspended=false
      gids=[3003]
      runtime permissions:
        android.permission.RECORD_AUDIO: granted=true, flags=[ USER_SET ]
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET ]
        android.permission.READ_SMS: granted=false, flags=[ USER_SET ]
      enabledComponents:
        com.whatsapp.Main
Hidden system packages:
  Package [com.android.ignored] (zzz):
    requested permissions:
      android.permission.READ_SMS
"""

LAUNCHER = """\
2 activities found:
  Activity #0:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.android.settings/.Settings
  Activity #1:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.whatsapp/.Main
"""

PS = """\
USER           PID NAME
root             1 init
u0_a150       4321 com.whatsapp
"""

DEVICE_POLICY = """\
Current Device Policy Manager state:
  Immutable state:
    mHasFeature=true
  Enabled Device Admins (User 0, provisioningState: 0):
    ComponentInfo{com.android.settings/com.android.settings.Admin}:
      uid=1000
"""

CONNECTIVITY_CLEAN = """\
NetworkAgentInfo{network{100}  handle{430} ni{WIFI CONNECTED extra: } Score{80}
  lp{{LinkProperties{InterfaceName: wlan0 LinkAddresses: [ 192.168.0.10/24 ] DnsAddresses: [ /192.168.0.1 ] Domains: null MTU: 0 Routes: [ 192.168.0.0/24 -> 0.0.0.0 wlan0 mtu 0,0.0.0.0/0 -> 192.168.0.1 wlan0 mtu 0 ]}}
"""

# ---- cenário "infectado" ------------------------------------------------------------

# Stalkerware: TheTruthSpy (com.systemservice), instalado fora da loja, sem ícone, com acessibilidade
SPY_PM = "package:/data/app/~~eA==/com.systemservice-1/base.apk=com.systemservice  installer=com.google.android.packageinstaller uid:10200\n"
SPY_DUMP = """\
  Package [com.systemservice] (777):
    userId=10200
    firstInstallTime=2099-01-01 10:00:00
    requested permissions:
      android.permission.READ_SMS
      android.permission.READ_CALL_LOG
      android.permission.RECEIVE_BOOT_COMPLETED
    install permissions:
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
    User 0: installed=true
      runtime permissions:
        android.permission.READ_SMS: granted=true
        android.permission.READ_CALL_LOG: granted=true
"""
# App desconhecido (não está na base) com combinação perigosa e permissões concedidas via ADB
SHADY_PM = ("package:/data/app/~~eA==/net.qwe.helper-1/base.apk=net.qwe.helper  installer=null uid:10201\n"
            "package:/data/app/~~eA==/com.anydesk.anydeskandroid-1/base.apk=com.anydesk.anydeskandroid  "
            "installer=com.android.vending uid:10202\n")
SHADY_DUMP = """\
  Package [net.qwe.helper] (888):
    userId=10201
    firstInstallTime=2020-01-01 10:00:00
    requested permissions:
      android.permission.READ_SMS
      android.permission.ACCESS_FINE_LOCATION
      android.permission.ACCESS_BACKGROUND_LOCATION
      android.permission.RECORD_AUDIO
      android.permission.WRITE_SECURE_SETTINGS
      android.permission.READ_LOGS
    install permissions:
      android.permission.WRITE_SECURE_SETTINGS: granted=true
      android.permission.READ_LOGS: granted=true
    User 0: installed=true
      runtime permissions:
        android.permission.READ_SMS: granted=true
        android.permission.ACCESS_FINE_LOCATION: granted=true
        android.permission.ACCESS_BACKGROUND_LOCATION: granted=true
        android.permission.RECORD_AUDIO: granted=true
"""
CONNECTIVITY_BAD = """\
NetworkAgentInfo{network{100}  handle{430} ni{WIFI CONNECTED extra: } Score{80}
  lp{{LinkProperties{InterfaceName: wlan0 LinkAddresses: [ 192.168.0.10/24 ] DnsAddresses: [ /192.168.0.1,/45.33.1.2 ] Domains: null MTU: 0 Routes: [ 0.0.0.0/0 -> 192.168.0.1 wlan0 mtu 0 ] HttpProxy: [10.0.0.9] 3128 xl}}
"""
WIFI_BAD = """\
WifiConfigManager - Configured networks Begin ----
  ID: 0 SSID: "CasaNet" PROVIDER-NAME: null BSSID: null
    KeyMgmt: WPA_PSK Protocols: WPA RSN
    IP config:
IP assignment: DHCP
Proxy settings: STATIC
HTTP proxy: [proxy.evil.lan] 8080 xl
  ID: 1 SSID: "Cafe" PROVIDER-NAME: null BSSID: null
    KeyMgmt: NONE
Proxy settings: NONE
WifiConfigManager - Configured networks End ----
"""
TELEPHONY_BAD = """\
  Phone Id=0
  mCallForwarding=true
  mServiceState={mVoiceRegState=0(IN_SERVICE), mDataRegState=0(IN_SERVICE), getRilVoiceRadioTechnology=16(GSM), getRilDataRadioTechnology=2(EDGE)}
"""
ACCOUNTS_BAD = """\
Accounts: 3
User UserInfo{0:Owner:c13}:
  Accounts: 3
    Account {name=vitima@gmail.com, type=com.google}
    Account {name=outra.pessoa@gmail.com, type=com.google}
    Account {name=sync, type=net.qwe.helper.account}
  RegisteredServicesCache: 2 services
    ServiceInfo: AuthenticatorDescription {type=com.google}, ComponentInfo{com.google.android.gms/com.google.android.gms.auth.GoogleAuth}, uid 10050
    ServiceInfo: AuthenticatorDescription {type=net.qwe.helper.account}, ComponentInfo{net.qwe.helper/net.qwe.helper.Auth}, uid 10201
"""
USERS_BAD = "Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Trabalho:1030} running\n"
BATTERY_BAD = """\
Battery History (1% used, 3kB used of 4096kB, 5 strings using 400B):
                    0 (10) RESET:TIME: 2026-10-01-10-00-00
      +1h00m00s000ms (2) 100 +pkginst=u0a99:"com.thetruth"
      +2h00m00s000ms (2) 100 +top=u0a99:"com.thetruth"
      +3h00m00s000ms (2) 100 -pkgunin=u0a99:"com.thetruth"
"""
# conexão ESTABELECIDA de net.qwe.helper (uid 10201) com 69.64.74.239:443 (C2 do TheTruthSpy)
PROC_NET_BAD = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A00A8C0:9C40 EF4A4045:01BB 01 00000000:00000000 00:00000000 00000000 10201        0 12345 1 0000000000000000 20 4 30 10 -1
   1: 0A00A8C0:9C41 0100A8C0:0035 01 00000000:00000000 00:00000000 00000000 10150        0 12346 1 0000000000000000 20 4 30 10 -1
"""
CACERTS_BAD = "\n".join([f"1230768000 /system/etc/security/cacerts/{i:08x}.0" for i in range(12)]
                        + ["1760000000 /system/etc/security/cacerts/c8750f0d.0"])
LOGCAT_BAD = "10-20 10:00:00.000 D/net( 999): connecting to api.flexispy.com\n"


class FakeDevice:
    serial = "FAKE123"

    def __init__(self, infected=False, patch="2099-01-01", extra=None):
        self.infected = infected
        pm, dump, third, ps = PM_LIST, DUMPSYS_PACKAGE, PM_THIRD, PS
        settings = {}
        self.responses = {
            "getprop": GETPROP.format(patch=patch, network="25001" if infected else "72410"),
            "pm list packages -f -i -U": pm,
            "pm list packages -3": third,
            "dumpsys package packages": dump,
            "cmd package query-activities --brief -a android.intent.action.MAIN "
            "-c android.intent.category.LAUNCHER": LAUNCHER,
            "ps -A -o USER,PID,NAME": ps,
            "dumpsys device_policy": DEVICE_POLICY,
            "getenforce": "Enforcing\n",
            "dumpsys connectivity": CONNECTIVITY_CLEAN,
            "pm list users": "Users:\n\tUserInfo{0:Owner:c13} running\n",
            "cat /proc/mounts": "/dev/block/dm-0 /system ext4 ro,seclabel 0 0\n",
        }
        if infected:
            self.responses.update({
                "pm list packages -f -i -U": pm + SPY_PM + SHADY_PM,
                "pm list packages -3": third + "package:com.systemservice\npackage:net.qwe.helper\n"
                                               "package:com.anydesk.anydeskandroid\n",
                "dumpsys package packages": dump.replace("Hidden system packages:",
                                                         SPY_DUMP + SHADY_DUMP + "Hidden system packages:"),
                "ps -A -o USER,PID,NAME": ps + "u0_a200       5555 com.systemservice\n",
                "dumpsys connectivity": CONNECTIVITY_BAD,
                "dumpsys wifi": WIFI_BAD,
                "dumpsys telephony.registry": TELEPHONY_BAD,
                "dumpsys account": ACCOUNTS_BAD,
                "pm list users": USERS_BAD,
                "pm list packages -3 --user 10": "package:com.vodaservices\n",
                "dumpsys batterystats --history": BATTERY_BAD,
                "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null": PROC_NET_BAD,
                "stat -c '%Y %n' /system/etc/security/cacerts/* 2>/dev/null": CACERTS_BAD,
                "cat /system/etc/security/cacerts/c8750f0d.0": "Subject: CN=mitmproxy, O=mitmproxy\n",
                "dumpsys notification --noredact":
                    "NotificationRecord(0x0a: pkg=android user=UserHandle{0} id=33 key=0|android|33|null|1000)\n",
                "logcat -d -b all -v time": LOGCAT_BAD,
                "cmd role get-role-holders --user 0 android.app.role.SMS": "net.qwe.helper\n",
                "ping -c 1 -W 1 www.google.com 2>&1": "PING www.google.com (10.0.0.66) 56(84) bytes of data.\n",
            })
            settings = {
                "secure enabled_accessibility_services": "com.systemservice/com.systemservice.Svc:net.qwe.helper/.A",
                "secure enabled_notification_listeners": "net.qwe.helper/.N",
                "global http_proxy": "10.0.0.5:8080",
                "global package_verifier_user_consent": "-1",
            }
        for k, v in settings.items():
            self.responses[f"settings get {k}"] = v + "\n"
        self.responses.update(extra or {})
        self.commands = []

    def shell(self, cmd, timeout=60):
        self.commands.append(cmd)
        if cmd in self.responses:
            value = self.responses[cmd]
            if isinstance(value, Exception):
                raise value
            return value
        if self.infected and cmd.startswith("ping") and "desgrampa-" in cmd:
            return "PING x (198.51.100.7) 56(84) bytes of data.\n"
        if self.infected and cmd.startswith("ls -d "):
            return "/data/local/tmp/wd\n"
        return "null\n" if cmd.startswith("settings ") else ""

    def pull(self, remote, local, timeout=300):
        raise AdbError("pull indisponível no aparelho falso")

    def bugreport(self, local_zip, timeout=900):
        raise AdbError("bugreport indisponível no aparelho falso")
