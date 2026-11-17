"""
Fake Netgear R6350 for testing PurrRouter without a real router.

Speaks the SOAP API (port 8099) and the web pages PurrRouter uses (Attached Devices, Port Forwarding, LAN Setup reservations, Wireless Setup, Logs, Router Status).
Login: admin / test.   Flags:
  --r6350   mimic R6350 firmware quirks (drops GetAttachDevice2, junk "BLOCK 44" header, no band info in SOAP)
  --xsrf    web pages want a token cookie handed out on the first 401
  --legacy  firmware without GetAttachDevice2 (answers 501)
Run:  python tools/mock-router/mock_router.py --r6350
Then in PurrRouter's setup screen: address 127.0.0.1, port 8099 (Advanced), password test.
"""
import re, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LEGACY = "--legacy" in sys.argv  # simulate firmware without GetAttachDevice2

DEVICES = [
    ("192.168.1.42", "ANDROID-PHONE", "7E:11:22:33:44:01", "2.4GHz", 72, "144", "HomeWiFi"),
    ("192.168.1.23", "WORK-LAPTOP", "54:11:22:33:44:02", "2.4GHz", 55, "72", "HomeWiFi"),
    ("192.168.1.31", "SMART-PLUG", "50:11:22:33:44:03", "2.4GHz", 61, "65", "HomeWiFi"),
    ("192.168.1.32", "DOORBELL-CAM", "50:11:22:33:44:04", "2.4GHz", 40, "39", "HomeWiFi"),
    ("192.168.1.33", "THERMOSTAT", "44:11:22:33:44:05", "2.4GHz", 66, "72", "HomeWiFi"),
    ("192.168.1.34", "SMART-BULB", "D0:11:22:33:44:06", "2.4GHz", 48, "54", "HomeWiFi"),
    ("192.168.1.35", "&lt;unknown&gt;", "90:11:22:33:44:07", "2.4GHz", 30, "24", "HomeWiFi"),
    ("192.168.1.43", "TABLET", "EE:11:22:33:44:08", "2.4GHz", 80, "72", "HomeWiFi"),
    ("192.168.1.20", "STREAMING-STICK", "3C:11:22:33:44:09", "5GHz", 90, "433", "HomeWiFi-5G"),
    ("192.168.1.10", "MEDIA-SERVER", "28:11:22:33:44:0A", "5GHz", 95, "866", "HomeWiFi-5G"),
    ("192.168.1.44", "PHONE-2", "32:11:22:33:44:0B", "5GHz", 70, "585", "HomeWiFi-5G"),
    ("192.168.1.36", "&lt;unknown&gt;", "68:11:22:33:44:0C", "5GHz", 52, "200", "HomeWiFi-5G"),
    ("192.168.1.21", "SMART-TV", "28:11:22:33:44:0D", "5GHz", 63, "400", "HomeWiFi-5G"),
    ("192.168.1.45", "IPHONE", "14:11:22:33:44:0E", "5GHz", 77, "780", "HomeWiFi-5G"),
    ("192.168.1.5", "DESKTOP-WIRED", "A8:11:22:33:44:0F", "wired", None, "1000", None),
]
BLOCKED = set()
TOKEN = None
RULES = [{"name": "web server", "ex": "8080-8080", "in": "80-80", "ip": "192.168.1.10", "proto": "1"},
         {"name": "Game server", "ex": "25565-25565", "in": "25565-25565", "ip": "192.168.1.23", "proto": "0"}]
GUEST = {"2.4": False, "5": False}
EDITING = 0
# Wireless Setup wrapper (WLG_dualband_idx.htm) hidden fields, same names/order as the R6350; fake values.
WL = dict(h_ssid_class="primary", h_ssidSelect="1", h_ssidSelect_an="1", tempSetting="0", tempRegion="11", setRegion="11",
          only_mode="0", warn_wpawpa2="0", warn_none_security="0", warn_wep_conflict_wps="0", warn_8021x_conflict_wps="0",
          ssid="HomeWiFi", h_ssid_bc="enable", h_WRegion="United States", h_w_channel="6", h_opmode="300", h_wire_iso="disable",
          h_wifi_badge_led_enable="", h_security_type="WPA2-PSK", h_authAlgm="3", h_wepenc="0", h_wep_key_no="1", h_wds="disable",
          h_wpae_mode="3", KEY1="", KEY2="", KEY3="", KEY4="", h_enable_ap="enable", h_enable_bss_coexist="enable",
          ssid_an="HomeWiFi-5G", h_wds_enable_an="disable", show_wps_alert="0", h_enable_ap_an="enable", h_ssid_bc_an="enable",
          h_allow_access="disable", h_allow_access_an="disable", h_wire_iso_an="disable", h_w_channel_an="149", h_opmode_an="450",
          h_security_type_an="WPA2-PSK", h_wepenc_an="0", h_wpae_mode_an="3", radius_rekey_secs="3600", radius_rekey_secs_an="3600",
          radiusServer="", radiusServer_an="", textWpaeRadiusPort="1812", textWpaeRadiusPort_an="1812", textWpaeRadiusSecret="",
          textWpaeRadiusSecret_an="", KEY1_an="", KEY2_an="", KEY3_an="", KEY4_an="", h_wep_key_no_an="1", h_authAlgm_an="3",
          passphrase="example-password", passphrase_an="example-password", wifi_smart_connect_enable="", todo="save",
          load_2g_frame="", load_5g_frame="", this_file="WLG_dualband_idx.htm", next_file="WLG_dualband_idx.htm", SID="")
WL_WRITABLE = {"ssid", "ssid_an", "passphrase", "passphrase_an", "h_w_channel", "h_w_channel_an", "h_ssid_bc", "h_ssid_bc_an"}
RESERVED = [{"ip": "192.168.1.10", "name": "MEDIA-SERVER", "mac": "28:11:22:33:44:0A"},
            {"ip": "192.168.1.5", "name": "DESKTOP-WIRED", "mac": "A8:11:22:33:44:0F"}]
# LAN Setup exactly as the R6350 reports it; a Delete/Edit post must echo these back unchanged.
LAN = {"device_name": "R6350", "c4_sysLANIPAddr": "192.168.1.1", "c4_sysLANSubnetMask": "255.255.255.0",
       "c4_sysPoolStartingAddr": "192.168.1.100", "c4_sysPoolFinishAddr": "192.168.1.254",
       "h_rip_direction": "both", "h_sysRIPVersion": "0", "h_dhcp_server": "enable", "h_wds": "disable", "h_apmode": "1"}
LAN_POSTED = {"h_rip_direction": "Both", "h_sysRIPVersion": "Disable", "rip_direction": "Both", "sysRIPVersion": "Disable",
              "dhcp_server": "dhcp_server", "sysLANIPAddr1": "192", "sysLANIPAddr4": "1", "sysLANSubnetMask4": "0",
              "sysPoolStartingAddr4": "100", "sysPoolFinishAddr4": "254"}
COOKIE = "sess_id=abc123; path=/"

FIELDS = {
    "DeviceInfo:1#GetInfo": dict(ModelName="R6350", Firmwareversion="V1.1.1.88", SerialNumber="TEST0000SERIAL",
                                FirstUseDate="Tuesday, 14 March 2023 09:42:07", DeviceName="R6350"),
    "WANIPConnection:1#GetInfo": dict(NewEnable="1", NewConnectionType="DHCP", NewExternalIPAddress="203.0.113.10",
                                      NewSubnetMask="255.255.252.0", NewAddressingType="DHCP", NewDefaultGateway="203.0.113.1",
                                      NewMACAddress="58:96:93:00:11:22", NewDNSServers="75.75.75.75 75.75.76.76"),
    "WANEthernetLinkConfig:1#GetEthernetLinkStatus": dict(NewEthernetLinkStatus="Up"),
    "LANConfigSecurity:1#GetInfo": dict(NewLANSubnet="255.255.255.0", NewLANMACAddress="58:96:93:00:11:21", NewLANIP="192.168.1.1", NewDHCPEnabled="true"),
    "WLANConfiguration:1#GetInfo": dict(NewEnable="1", NewSSIDBroadcast="1", NewStatus="Up", NewSSID="HomeWiFi", NewChannel="6", NewWirelessMode="Up to 300 Mbps", NewWPAEncryptionModes="WPA2-PSK"),
    "WLANConfiguration:1#Get5GInfo": dict(NewEnable="1", NewSSIDBroadcast="1", NewStatus="Up", NewSSID="HomeWiFi-5G", NewChannel="149", NewWirelessMode="Up to 1300 Mbps", NewWPAEncryptionModes="WPA2-PSK"),
    "WLANConfiguration:1#GetWPASecurityKeys": dict(NewWPAPassphrase="example-password"),
    "WLANConfiguration:1#Get5GWPASecurityKeys": dict(NewWPAPassphrase="example-password"),
    "DeviceConfig:1#GetTrafficMeterEnabled": dict(NewTrafficMeterEnable="1"),
    "DeviceConfig:1#GetTrafficMeterStatistics": dict(NewTodayConnectionTime="17:45", NewTodayUpload="1,204.55", NewTodayDownload="18,330.12",
        NewYesterdayConnectionTime="24:00", NewYesterdayUpload="2210.10", NewYesterdayDownload="25350.10",
        NewWeekConnectionTime="161:45", NewWeekUpload="9100.20/1300.03", NewWeekDownload="120345.50/17192.21",
        NewMonthConnectionTime="353:45", NewMonthUpload="20450.66/1363.38", NewMonthDownload="301234.88/20082.33",
        NewLastMonthConnectionTime="744:00", NewLastMonthUpload="40120.11/1294.20", NewLastMonthDownload="610993.71/19709.47"),
    "DeviceConfig:1#GetBlockDeviceEnableStatus": dict(NewBlockDeviceEnable="1"),
}


def env(method, svc, inner, code="000"):
    return f"""<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body><m:{method}Response xmlns:m="urn:NETGEAR-ROUTER:service:{svc}">{inner}</m:{method}Response>
<ResponseCode>{code}</ResponseCode></SOAP-ENV:Body></SOAP-ENV:Envelope>"""


def code_only(code):
    return f'<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><ResponseCode>{code}</ResponseCode></SOAP-ENV:Body></SOAP-ENV:Envelope>'


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # claim keep-alive...
    def log_message(self, *a): pass

    def send(self, body, cookie=None, junk=None):
        b = body.encode()
        self.send_response(200)
        if junk: self._headers_buffer.append(junk.encode() + b"\r\n")  # R6350 emits a bare "BLOCK 44" line
        self.send_header("Content-Type", "text/xml")
        if cookie: self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
        if "--rude" in sys.argv: self.close_connection = True  # ...but hang up anyway, no Connection: close header

    def web_auth_ok(self):
        import base64
        ok_auth = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:test").decode()
        ok_cookie = "--xsrf" not in sys.argv or "XSRF_TOKEN=abc999" in (self.headers.get("Cookie") or "")
        return ok_auth and ok_cookie

    def html(self, text, status=200):
        b = text.encode(); self.send_response(status); self.send_header("Content-Type","text/html"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)

    def fw_list_page(self):
        global TOKEN
        import secrets, html as H
        TOKEN = secrets.token_hex(8)
        rows = "".join(f"""<tr>
<td nowrap align=center>&nbsp;<input type="RADIO" name="RouteSelect" value="{i+1}">&nbsp;</td>
<td nowrap align=center><span class=thead>{i+1}</span></td>
<td nowrap align=center><span class=ttext>{H.escape(r['name']).replace(' ', '&nbsp;')}</span></td>
<td nowrap align=center><span class=ttext>{r['ex']}</span></td>
<td nowrap align=center><span class=ttext>{r['in']}</span></td>
<td nowrap align=center><span class=ttext>{r['ip']}</span></td>
<td nowrap align=center style="display:none">57</td></tr>""" for i, r in enumerate(RULES))
        return f"""<html><body><form name="formname" method="POST" action="setup.cgi?id={TOKEN}">
<TABLE class="tables" id="PortForwarding"><TR class="table_header"><td>x</td></tr>{rows}
<!-- <tr><td nowrap align=center>&nbsp;<input type="RADIO" name="RouteSelect" value="1">&nbsp;</td><td><span class=thead>1</span></td><td><span class=ttext>FTP</span></td><td><span class=ttext>20</span></td><td><span class=ttext>21</span></td><td><span class=ttext>192.168.1.99</span></td></tr> -->
</table>
<input type="hidden" name="lanIP" value="192.168.1.1">
<input type="hidden" name="todo" value="pfw_add"><input type="hidden" name="SID" value="">
</form></body></html>"""

    def fw_service_page(self, rule=None, idx=0):
        global TOKEN
        import secrets, html as H
        TOKEN = secrets.token_hex(8)
        r = rule or {"name": "", "ex": "", "in": "", "ip": "", "proto": ""}
        return f"""<html><body><form name="formname" action="setup.cgi?id={TOKEN}" method="POST">
<input type="text" name="portname" size="30" maxlength="30" value="{H.escape(r['name'])}">
<input type="text" class="num" name="ex_port_range" value="{r['ex']}"><input type="text" class="num" name="in_port_range" value="{r['in']}">
<input type="hidden" name="h_ruleSelect" value="{idx}"><input type="hidden" name="lanIP" value="192.168.1.1">
<input type="hidden" name="h_srvtype" value="{r['proto']}"><input type="hidden" name="c4_server_ip" value="{r['ip']}">
<input type="hidden" name="SID" value=""></form></body></html>"""

    def lan_page(self):
        global TOKEN
        import secrets
        TOKEN = secrets.token_hex(8)
        rows = "".join(f"{r['ip']}{r['name']}{r['mac']}" for r in RESERVED)
        hidden = "".join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in LAN.items() if k != "device_name")
        return f"""<html><head><script><!--
function print_all_reserve()
{{
	var all_reserve = "{rows}";
}}
//--></script></head><body><form name="frmLan" method="POST" action="setup.cgi?id={TOKEN}">
<input type="text" maxlength="12" size="24" name="device_name" value="{LAN['device_name']}">
<input type="checkbox" name="dhcp_server" value="dhcp_server">
{hidden}<input type="hidden" name="h_ruleSelect" value=""><input type="hidden" name="todo" value="save">
<input type="hidden" name="this_file" value="LAN_lan.htm"><input type="hidden" name="next_file" value="LAN_lan.htm"><input type="hidden" name="SID" value="">
</form></body></html>"""

    def rsv_page(self, this_file, r=None):
        global TOKEN
        import secrets
        TOKEN = secrets.token_hex(8)
        r = r or {"ip": "", "name": "", "mac": ""}
        return f"""<html><body><form method="POST" action="setup.cgi?id={TOKEN}">
{'<input class="apply_bt" type="SUBMIT" name="apply" value=" Apply ">' if this_file.endswith("edit.htm") else '<input class="apply_bt" type="SUBMIT" name="Add" value=" Add ">'}
<input type="text" name="rsv_ip1" value=""><input type="text" name="rsv_ip2" value=""><input type="text" name="rsv_ip3" value=""><input type="text" name="rsv_ip4" value="">
<input type="text" name="rsv_mac" class="num" size="17" maxlength="17" value="{r['mac']}">
<input type="text" name="dv_name" size="20" maxlength="20" value="{r['name']}">
{'<input type="hidden" name="todo" value="save"><input type="hidden" name="h_ruleSelect" value="' + str(EDITING) + '"><input type="hidden" name="c4_rsv_ip" value="' + r['ip'] + '"><input type="hidden" name="edit" value="1">' if this_file.endswith("edit.htm") else '<input type="hidden" name="c4_rsv_ip" value="192.168.1."><input type="hidden" name="todo" value="save">'}
<input type="hidden" name="this_file" value="{this_file}"><input type="hidden" name="next_file" value="LAN_lan.htm"><input type="hidden" name="SID" value="">
</form></body></html>"""

    def wl_pages(self, path):
        global TOKEN
        import secrets, html as H
        if path.startswith("/WLG_dualband_idx.htm"):
            TOKEN = secrets.token_hex(8)
            hidden = "".join(f'<input type="hidden" name="{k}" value="{H.escape(v)}">' for k, v in WL.items())
            return f'<html><head><script>var SKU = "NA";</script></head><body><form method="POST" action="setup.cgi?id={TOKEN}">{hidden}</form></body></html>'
        on = lambda k: H.escape(WL[k])
        if path.startswith("/WLG_2g_wireless2.htm"):
            return f"""<html><body><form method="POST" action="setup.cgi??id=iframe24&sp=2">
<input type="text" name="ssid" value="{on('ssid')}"><input type="checkbox" name="enable_bssid" value="enable_bssid"><input type="checkbox" name="ssid_bc" value="ssid_bc">
<input type="text" name="passphrase" value="{on('passphrase')}"><input type="hidden" name="h_enable_bssid" value="enable"><input type="hidden" name="h_ssid_bc" value="{on('h_ssid_bc')}">
<input type="hidden" name="h_w_channel" value="{on('h_w_channel')}"><input type="hidden" name="h_opmode" value="{on('h_opmode')}"><input type="hidden" name="h_security_type" value="{on('h_security_type')}">
<input type="hidden" name="h_ssidSelect" value="1"><input type="hidden" name="h_enable_bss_coexist" value="enable"></form></body></html>"""
        if path.startswith("/WLG_5g_wireless2.htm"):
            return f"""<html><body><form method="POST" action="setup.cgi??id=iframe5&sp=2">
<input type="text" name="ssid_an" value="{on('ssid_an')}"><input type="text" name="passphrase_an" value="{on('passphrase_an')}">
<input type="hidden" name="h_enable_bssid_an" value="enable"><input type="hidden" name="h_ssid_bc_an" value="{on('h_ssid_bc_an')}">
<input type="hidden" name="h_w_channel_an" value="{on('h_w_channel_an')}"><input type="hidden" name="h_opmode_an" value="{on('h_opmode_an')}">
<input type="hidden" name="h_security_type_an" value="{on('h_security_type_an')}"><input type="hidden" name="h_ssidSelect_an" value="1"></form></body></html>"""
        if path.startswith("/WLG_dualband_adv.htm"):
            return '<html><body><form method="POST" action="setup.cgi?id=adv"><input type="hidden" name="h_enable_ap" value="enable"><input type="hidden" name="h_enable_ap_an" value="enable"></form></body></html>'
        return None

    def admin_pages(self, path):
        if path.startswith("/FW_log.htm"):
            lines = ["[admin login] from source 192.168.1.23 Monday, November 16,2026 20:26:20",
                     "[Access Control] Device THERMOSTAT with MAC address 44:11:22:33:44:05 is allowed to acces Monday, November 16,2026 20:24:40",
                     "[LAN access from remote] from 198.51.100.7:25728 to 192.168.1.10:8080 Monday, November 16,2026 20:24:23",
                     "[DHCP IP: (192.168.1.43)] to MAC address EE:11:22:33:44:08, Monday, November 16,2026 20:20:01",
                     "[Internet connected] IP address: 203.0.113.10, Monday, November 16,2026 08:00:00",
                     "[Time synchronized with NTP server] Monday, November 16,2026 07:59:58",
                     "[Access Control] Device UNKNOWN with MAC address 90:1"]
            return '<html><body><form action="setup.cgi?id=log"><textarea name="log_detail" readonly>' + "\n".join(l + "        " for l in lines) + "</textarea></form></body></html>"
        if path.startswith("/RST_stattbl.htm"):
            row = lambda *c: "<tr>" + "".join(f"<td>{x}</td>" for x in c) + "</tr>"
            return ("<html><body><table>" + row("System Up Time", "52:10:07") + row("Port", "Status", "TxPkts", "RxPkts", "Collisions", "Tx B/s", "Rx B/s", "Up Time")
                    + row("WAN", "1000M/Full", "1200", "3400", "0", "5000", "16000", "50:00:01") + row("LAN 1", "1000M/Full", "100", "200", "0", "20", "30", "52:09:50")
                    + row("LAN 2", "Link down", "--") + row("2.4G WLAN b/g/n", "300M", "10", "20", "0", "1", "2", "52:10:00") + row("5G WLAN a/n/ac", "1733M", "10", "20", "0", "1", "2", "52:10:00")
                    + "</table></body></html>")
        if path.startswith("/RST_wanstat.htm"):
            return '<html><head><meta http-equiv="REFRESH" content="0; URL= setup.cgi?next_file=RST_st_dhcp.htm"></head><body></body></html>'
        if path.startswith("/setup.cgi?next_file=RST_st_dhcp.htm"):
            row = lambda a, b: f"<tr><td>{a}</td><td>{b}</td></tr>"
            return ("<html><body><table>" + row("IP Address", "203.0.113.10") + row("Subnet Mask", "255.255.252.0") + row("Default Gateway", "203.0.113.1")
                    + row("DHCP Server :", "203.0.113.2") + row("DNS Server :", "75.75.75.75 75.75.76.76") + row("Lease Obtained", "0 days,3 hrs,0 minutes")
                    + row("Lease Expires", "0 days,21 hrs,0 minutes") + "</table></body></html>")
        return None

    def do_GET(self):
        import base64
        if self.path.startswith(("/FW_log.htm", "/RST_", "/setup.cgi?next_file=RST_")):
            if not self.web_auth_ok(): return self.html("", 401)
            page = self.admin_pages(self.path)
            if page is not None: return self.html(page)
        if self.path.startswith("/WLG_"):
            if not self.web_auth_ok(): return self.html("", 401)
            page = self.wl_pages(self.path)
            if page is not None: return self.html(page)
        if self.path.startswith("/LAN_lan.htm"):
            if not self.web_auth_ok(): return self.html("", 401)
            return self.html(self.lan_page())
        if self.path.startswith("/LAN_reserv_add.htm"):
            if not self.web_auth_ok(): return self.html("", 401)
            return self.html(self.rsv_page("LAN_reserv_add.htm"))
        if self.path.startswith("/FW_forward.htm"):
            if not self.web_auth_ok(): return self.html("", 401)
            return self.html(self.fw_list_page())
        if self.path.startswith("/setup.cgi?todo=nbtscan&next_file=FW_forward_service.htm"):
            if not self.web_auth_ok(): return self.html("", 401)
            return self.html(self.fw_service_page())
        if not self.path.startswith("/setup.cgi"):
            self.send_response(404); self.send_header("Content-Length","0"); self.end_headers(); return
        ok_auth = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:test").decode()
        ok_cookie = "--xsrf" not in sys.argv or "XSRF_TOKEN=abc999" in (self.headers.get("Cookie") or "")
        if not (ok_auth and ok_cookie):
            self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="NETGEAR R6350"')
            if "--xsrf" in sys.argv: self.send_header("Set-Cookie", "XSRF_TOKEN=abc999; path=/")
            self.send_header("Content-Length","0"); self.end_headers(); return
        row = lambda d: f'<tr><td><span languageCode="3912">Allowed</span></td><td><b>{d[6] or ""}</b></td><td><b>{d[0]}</b></td><td><b>{d[2]}</b></td><td><b>{d[1]}</b></td></tr>'
        html = ("<html><body>Wired Devices<table>" + "".join(row(d) for d in DEVICES if d[3]=="wired")
                + "</table>2.4GHz Wireless Devices (Wireless intruders also show up here)<table>" + "".join(row(d) for d in DEVICES if d[3]=="2.4GHz")
                + "</table>5GHz Wireless Devices (Wireless intruders also show up here)<table>" + "".join(row(d) for d in DEVICES if d[3]=="5GHz")
                + "</table>VPN Client Devices<table></table></body></html>")
        b = html.encode(); self.send_response(200); self.send_header("Content-Type","text/html"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
        print("WEB", self.path, flush=True)

    def do_POST(self):
        if self.path.startswith("/setup.cgi?id="):
            from urllib.parse import parse_qs
            if not self.web_auth_ok(): return self.html("", 401)
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            f = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
            print("WEB POST", f.get("todo"), f.get("this_file"), {k: f.get(k) for k in ("h_pfw_name","c4_pfw_ip","h_pfw_proto","h_pfw_ex_range","h_pfw_in_range","ruleSelect","edit","dv_name","c4_rsv_ip","rsv_mac")}, flush=True)
            if self.path.split("=",1)[1] != TOKEN:
                return self.html("<script>alert('Session expired')</script>")   # stale token: router ignores
            todo = f.get("todo")
            if f.get("this_file") == "WLG_dualband_idx.htm" and todo == "save":
                expect = {**WL, "load_2g_frame": "WLG_2g_wireless2.htm", "load_5g_frame": "WLG_5g_wireless2.htm"}
                bad = {k: (f.get(k), v) for k, v in expect.items() if k not in WL_WRITABLE and f.get(k) != v}
                extra = set(f) - set(WL)
                if bad or extra or list(f) != list(WL):
                    print("WIFI FORM MISMATCH", bad, extra, flush=True)
                    return self.html("<script>alert('wifi form mismatch')</script>")
                for k in WL_WRITABLE: WL[k] = f[k]
                return self.html(self.wl_pages("/WLG_dualband_idx.htm"))
            if f.get("this_file") == "LAN_lan.htm":   # Edit/Delete post the whole LAN Setup form
                bad = {k: f.get(k) for k, v in {**{k: v for k, v in LAN.items() if k.startswith("c4_") or k in ("device_name", "h_dhcp_server", "h_wds", "h_apmode")}, **LAN_POSTED}.items() if f.get(k) != v}
                if bad or f.get("ruleSelect") != f.get("h_ruleSelect"):
                    print("LAN FORM MISMATCH", bad, flush=True)
                    return self.html("<script>alert('LAN form mismatch')</script>")
                n = int(f["ruleSelect"])
                if todo == "delete": RESERVED.pop(n); return self.html(self.lan_page())
                if todo == "edit": global EDITING; EDITING = n; return self.html(self.rsv_page("LAN_reserv_edit.htm", RESERVED[n]))
            if f.get("this_file") in ("LAN_reserv_add.htm", "LAN_reserv_edit.htm") and todo == "save":
                ip = ".".join(f[f"rsv_ip{k}"] for k in range(1, 5))
                if ip != f.get("c4_rsv_ip"): return self.html("<script>alert('ip mismatch')</script>")
                r = {"ip": ip, "name": f["dv_name"], "mac": f["rsv_mac"].upper()}
                if f["this_file"] == "LAN_reserv_edit.htm":
                    if f.get("edit") != "1" or f.get("h_ruleSelect") != str(EDITING) or "apply" not in f: return self.html("<script>alert('edit form mismatch')</script>")
                    RESERVED[EDITING] = r
                else:
                    RESERVED[:] = [x for x in RESERVED if x["ip"] != r["ip"] and x["mac"] != r["mac"]] + [r]
                return self.html(self.lan_page())
            if todo == "edit":
                n = int(f["ruleSelect"]); r = RULES[n-1]
                return self.html(self.fw_service_page(r, n))
            if todo == "delete":
                n = int(f["ruleSelect"]); RULES.pop(n-1)
                return self.html(self.fw_list_page())
            if todo == "pfw_add":
                rule = {"name": f["h_pfw_name"], "ex": f["h_pfw_ex_range"], "in": f["h_pfw_in_range"], "ip": f["c4_pfw_ip"], "proto": f["h_pfw_proto"]}
                if f.get("edit") == "1": RULES[int(f["ruleSelect"])-1] = rule
                else: RULES.append(rule)
                return self.html(self.fw_list_page())
            return self.html("?")
        if "--netgear" in sys.argv:
            n = getattr(self, "_served", 0); self._served = n + 1
            if n >= 1:  # 2nd request on a kept-alive connection: hang up without answering
                self.close_connection = True
                return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        action = self.headers.get("SOAPAction", "").replace("urn:NETGEAR-ROUTER:service:", "")
        svc, method = action.split("#")
        print("SOAP", action, flush=True)

        if method == "SOAPLogin":
            pw = re.search(r"<Password>(.*?)</Password>", body)
            return self.send(env(method, svc, "")) if False else (
                self.send(env(method, svc, ""), COOKIE) if pw and pw.group(1) == "test" else self.send(code_only(401)))
        if method == "Authenticate":
            return self.send(code_only(401))
        if self.headers.get("Cookie") != COOKIE:
            return self.send(code_only(401))

        if action in FIELDS:
            return self.send(env(method, svc, "".join(f"<{k}>{v}</{k}>" for k, v in FIELDS[action].items())))
        if method == "GetAttachDevice2":
            if "--r6350" in sys.argv: self.close_connection = True; return  # hang up, like the real one
            if LEGACY: return self.send(code_only(501))
            xml = "".join(
                f"<Device><IP>{ip}</IP><Name>{n}</Name><MAC>{mac}</MAC><ConnectionType>{ct}</ConnectionType>"
                f"<SSID>{ssid or ''}</SSID><Linkspeed>{ls}</Linkspeed><SignalStrength>{sig if sig is not None else ''}</SignalStrength>"
                f"<AllowOrBlock>{'Block' if mac in BLOCKED else 'Allow'}</AllowOrBlock></Device>"
                for ip, n, mac, ct, sig, ls, ssid in DEVICES)
            return self.send(env(method, svc, f"<NewAttachDevice>{xml}</NewAttachDevice>"))
        if method == "GetAttachDevice":
            s = f"{len(DEVICES)}" + "".join(
                f"@{i+1};{ip};{n};{mac};{('wireless' if ct != 'wired' else 'wired') if '--r6350' in sys.argv else ct};{ls};{sig or ''};{'Block' if mac in BLOCKED else 'Allow'}"
                for i, (ip, n, mac, ct, sig, ls, ssid) in enumerate(DEVICES))
            return self.send(env(method, svc, f"<NewAttachDevice>{s}</NewAttachDevice>"))
        if method in ("GetGuestAccessEnabled",):
            return self.send(env(method, svc, f"<NewGuestAccessEnabled>{int(GUEST['2.4'])}</NewGuestAccessEnabled>"))
        if method in ("Get5GGuestAccessEnabled",):
            return self.send(env(method, svc, f"<NewGuestAccessEnabled>{int(GUEST['5'])}</NewGuestAccessEnabled>"))
        if method == "SetGuestAccessEnabled":
            GUEST["2.4"] = "<NewGuestAccessEnabled>1" in body; return self.send(env(method, svc, ""))
        if method == "Set5GGuestAccessEnabled":
            GUEST["5"] = "<NewGuestAccessEnabled>1" in body; return self.send(env(method, svc, ""))
        if method in ("ConfigurationStarted", "ConfigurationFinished", "Reboot"):
            return self.send(env(method, svc, ""))
        if method == "SetBlockDeviceByMAC":
            mac = re.search(r"<NewMACAddress>(.*?)</NewMACAddress>", body).group(1)
            blk = "<NewAllowOrBlock>Block" in body
            (BLOCKED.add if blk else BLOCKED.discard)(mac)
            return self.send(env(method, svc, ""), junk=("BLOCK 44" if blk else "ALLOW 44") if "--r6350" in sys.argv else None)
        return self.send(code_only(501))


ThreadingHTTPServer(("127.0.0.1", 8099), H).serve_forever()
