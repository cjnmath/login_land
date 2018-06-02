import requests
import re
import json
import urllib
import base64
import rsa
import binascii
from random import choice
from lxml.html import fromstring


DESKTOP_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063'
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/65.0.3325.181 Chrome/65.0.3325.181 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.75 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36 OPR/47.0.2631.55',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5']


class weibo_desktop:
    """ for weibo webpage(v1.4.19) login

        input:
            username (str)
            password (str)

        attribute:
            username (str)
            password (str)
            use_id (str): the unique internal id for username
            seeeion (requests.Session): an api for further scrapying
            root (lxml.html): for home page xpath and css selector

    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.user_id, self.session, self.root = self.login()

    def login(self):
        url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Content-Length': '839',
            'Content-Type': 'application/x-www-form-urlencoded',
            'DNT': '1',
            'Host': 'login.sina.com.cn',
            'Origin': 'https://weibo.com',
            'Referer': 'https://weibo.com/',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': choice(DESKTOP_USER_AGENTS)}
        # the login contains three redirection
        session = requests.Session()
        prelogin_data = self.get_prelogin_args()
        #
        response = session.post(url,
                                headers=headers,
                                data=self.build_post_data(prelogin_data))
        response.encoding = 'GBK'
        url_pattern = re.compile('location\.replace\(\"(.*)\"\)')
        login_url = url_pattern.search(response.text).group(1)
        redirect_response = session.get(login_url)
        redirect_response.encoding = 'GBK'
        redirect_url_pattern = re.compile('location\.replace\(\'(.*)\'\)')
        redirect_url = redirect_url_pattern.search(redirect_response.text).group(1)
        real_response = session.get(redirect_url)
        json_pattern = re.compile('feedBackUrlCallBack\((.*)\)')
        data = json.loads(json_pattern.search(real_response.text).group(1))
        userdomain = data['userinfo']['userdomain']
        uniqueid = data['userinfo']['uniqueid']
        final_url = 'https://weibo.com/u/{}/home{}'.format(uniqueid, userdomain)
        final_response = session.get(final_url)
        # self.home_url = final_response.url
        final_response.encoding = 'UTF-8'
        root = fromstring(final_response.text)
        return uniqueid, session, root

    def get_prelogin_args(self):
        """ the prelog data contains the rsa public key and other neccessary information to login
            it is somthing like this :
            {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': 'https://passport.weibo.com/visitor/visitor?entry=miniblog&a=enter&url=https%3A%2F%2Fweibo.com%2F&domain=.weibo.com&ua=php-sso_sdk_client-0.6.28&_rand=1524785463.8471',
            'vsnf': '1',
            'su': 'Y2pubWF0aCU0MDEyNi5jb20=',
            'service': 'miniblog',
            'servertime': '1524785533',
            'nonce': 'NE1OVR',
            'pwencode': 'rsa2',
            'rsakv': '1330428213',
            'sp': '60f6dd8c3d28794277e218e5829887c7a97167c842981f4bead3864c6dd42b897ba7a7a2540314e873e603ba688dbfdf470fb404fd571cd5497e23075231a8f55b42',
            'sr': '1920*1080',
            'encoding': 'UTF-8',
            'prelt': '31',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
            }

            'su' represents the encrypted username
            'sp' reppresents the rsa encrypted password
        """
        # " su=******** " the ******** is a token encoding (base64) from weibo username
        url = 'https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su={}&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)'
        json_pattern = re.compile('\((.*)\)')
        response = requests.post(url.format(self.get_encrypted_name()))
        data = json.loads(json_pattern.search(response.text).group(1))
        return data

    def get_encrypted_name(self):
        # first, change user name to url encoding,
        # e.g. "@" would be encoding in "%40"
        # or ursing somthing like this:
        # username_urllike = urllib.request.path2ulr(self.username)
        username_urllike = urllib.request.quote(self.username)
        # then encoding in base64
        # but has to encode in byte like before pass in
        # because b64encode only accept byte
        username_encrypted = base64.b64encode(username_urllike.encode('utf-8'))
        return username_encrypted.decode('utf-8')

    def get_encrypted_password(self, data):
        """ the password was transmited after (rsa) encrypted
        """
        rsa_e = 65537  # 0x10001 in hexadecimal
        # the password was not encrypted directively
        # instead it encrypts the string with addiction of severtime and nonce
        # you can get this informationg by examming its codes in ssologin.js
        pw_string = '\t'.join([str(data['servertime']), str(data['nonce'])]) + '\n' + self.password
        # the key we get in prelogin data was in hexadecimal
        # we have to translate it to decimal first
        key = rsa.PublicKey(int(data['pubkey'], 16), rsa_e)
        # do the encryption
        pw_encypted = rsa.encrypt(pw_string.encode('utf-8'), key)
        self.password = ''  # clean the password for safty concern
        # again anything needed to be transmitted trought network
        # it has to be in hexadecimal encoded
        password = binascii.b2a_hex(pw_encypted)
        return password

    def build_post_data(self, data):
        post_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': 'https://passport.weibo.com/visitor/visitor?entry=miniblog&a=enter&url=https%3A%2F%2Fweibo.com%2F&domain=.weibo.com&ua=php-sso_sdk_client-0.6.28',
            'vsnf': '1',
            'su': self.get_encrypted_name(),
            'service': 'miniblog',
            'servertime': data['servertime'],
            'nonce': data['nonce'],
            'pwencode': 'rsa2',
            'rsakv': data['rsakv'],
            'sp': self.get_encrypted_password(data),
            'sr': '1920*1080',
            'encoding': 'UTF-8',
            'prelt': '31',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'}
        return post_data
