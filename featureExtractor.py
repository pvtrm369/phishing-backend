import re
import requests
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
import dns.resolver
from datetime import datetime
import socket




allbrand_txt = open("allbrands.txt", "r")

def __txt_to_list(txt_object):
    list = []
    for line in txt_object:
        list.append(line.strip())
    txt_object.close()
    return list

allbrand = __txt_to_list(allbrand_txt)

# Helper functions for feature extraction
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    return 1 if match else 0

def url_length(url):
    return len(url)

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_at(url):
    return url.count('@')

def count_qm(url):
    return url.count('?')

def count_and(url):
    return url.count('&')

def count_or(url):
    return url.count('|')

def count_eq(url):
    return url.count('=')

def count_underscore(url):
    return url.count('_')

def count_tilde(url):
    return url.count('~')

def count_percent(url):
    return url.count('%')

def count_slash(url):
    return url.count('/')

def count_star(url):
    return url.count('*')

def count_colon(url):
    return url.count(':')

def count_comma(url):
    return url.count(',')

def count_semicolumn(url):
    return url.count(';')

def count_dollar(url):
    return url.count('$')

def count_space(url):
    return url.count(' ') + url.count('%20')

def count_www(words_raw):
    return sum(1 for word in words_raw if 'www' in word)

def count_com(words_raw):
    return sum(1 for word in words_raw if 'com' in word)

def count_dslash(url):
    return url.count('//')

def http_in_path(path):
    return path.count('http')

def https_token(scheme):
    return 1 if scheme == 'https' else 0

def ratio_digits(url):
    digits = re.sub("[^0-9]", "", url)
    return len(digits) / len(url) if len(url) > 0 else 0

def punycode(url):
    return 1 if url.startswith("http://xn--") or url.startswith("https://xn--") else 0

def port(url):
    return 1 if re.search(":\d+", url) else 0

def tld_in_path(tld, path):
    return 1 if tld in path else 0

def tld_in_subdomain(tld, subdomain):
    return 1 if tld in subdomain else 0

def abnormal_subdomain(url):
    return 1 if re.search('(http[s]?://(w[w]?|\d))([w]?(\d|-))', url) else 0

def count_subdomain(url):
    return len(url.split('.'))

def prefix_suffix(url):
    return 1 if re.findall(r"https?://[^\-]+-[^\-]+/", url) else 0

def random_domain(domain):
    # Implement your logic to check if the domain is random
    return 0

def shortening_service(url):
    shorteners = ['bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs',
                  'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
                  'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
                  'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.co', 'lnkd.in',
                  'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im',
                  'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org',
                  'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd',
                  'tr.im', 'link.zip.net']
    return 1 if any(shortener in url for shortener in shorteners) else 0

def path_extension(path):
    return 1 if path.endswith('.txt') else 0

def count_redirection(page):
    return len(page.history) if hasattr(page, 'history') else 0

def count_external_redirection(page, domain):
    if not hasattr(page, 'history'):
        return 0
    return sum(1 for response in page.history if domain.lower() not in response.url.lower())

def length_words_raw(words_raw):
    return len(words_raw)

def char_repeat(words_raw):
    repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
    for word in words_raw:
        for char_repeat_count in [2, 3, 4, 5]:
            for i in range(len(word) - char_repeat_count + 1):
                sub_word = word[i:i + char_repeat_count]
                if all(x == sub_word[0] for x in sub_word):
                    repeat[str(char_repeat_count)] += 1
    return sum(repeat.values())

def shortest_words_raw(words_raw):
    return min(len(word) for word in words_raw) if words_raw else 0

def longest_words_raw(words_raw):
    return max(len(word) for word in words_raw) if words_raw else 0

def avg_words_raw(words_raw):
    return sum(len(word) for word in words_raw) / len(words_raw) if words_raw else 0

def phish_hints(url):
    hints = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']
    return sum(url.lower().count(hint) for hint in hints)

def domain_in_brand(domain):
    if domain in allbrand:
            return 1
    else:
        return 0

def brand_in_subdomain(domain, subdomain):
    # Implement your logic to check if the brand is in the subdomain
    return 0

def brand_in_path(domain, path):
     for b in allbrand:
        if '.'+b+'.' in path and b not in domain:
           return 1
     return 0

def suspecious_tld(tld):
    suspecious_tlds = ['fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click', 'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
                       'ren', 'mom', 'party', 'review', 'trade', 'accountants', 'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
                       'accountant', 'realtor', 'top', 'christmas', 'gdn', 'link', 'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
                       'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au']
    return 1 if tld in suspecious_tlds else 0

def statistical_report(url, domain):
  url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
  try:
        ip_address=socket.gethostbyname(domain)
        ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                           '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                           '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                           '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                           '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                           '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
        if url_match or ip_match:
            return 1
        else:
            return 0
  except:
        return 2

def nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
        return len(Href['internals']) + len(Href['externals']) +\
               len(Link['internals']) + len(Link['externals']) +\
               len(Media['internals']) + len(Media['externals']) +\
               len(Form['internals']) + len(Form['externals']) +\
               len(CSS['internals']) + len(CSS['externals']) +\
               len(Favicon['internals']) + len(Favicon['externals'])

def ratio_intHyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
    internals = len(Href['internals']) + len(Link['internals']) + len(Media['internals']) + len(Form['internals']) + len(CSS['internals']) + len(Favicon['internals'])
    return internals / total if total > 0 else 0

def ratio_extHyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
    externals = len(Href['externals']) + len(Link['externals']) + len(Media['externals']) + len(Form['externals']) + len(CSS['externals']) + len(Favicon['externals'])
    return externals / total if total > 0 else 0

def ratio_nullHyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
    nulls = len(Href['null']) + len(Link['null']) + len(Media['null']) + len(Form['null']) + len(CSS['null']) + len(Favicon['null'])
    return nulls / total if total > 0 else 0

def nb_extCSS(CSS):
    return len(CSS['externals'])

def ratio_intRedirection(Href, Link, Media, Form, CSS, Favicon):
    internals = len(Href['internals']) + len(Link['internals']) + len(Media['internals']) + len(Form['internals']) + len(CSS['internals']) + len(Favicon['internals'])
    redirects = sum(1 for link in Href['internals'] + Link['internals'] + Media['internals'] + Form['internals'] + CSS['internals'] + Favicon['internals'] if requests.get(link).history)
    return redirects / internals if internals > 0 else 0

def ratio_extRedirection(Href, Link, Media, Form, CSS, Favicon):
    externals = len(Href['externals']) + len(Link['externals']) + len(Media['externals']) + len(Form['externals']) + len(CSS['externals']) + len(Favicon['externals'])
    redirects = 0
    for link in Href['externals'] + Link['externals'] + Media['externals'] + Form['externals'] + CSS['externals'] + Favicon['externals']:
        # Check if the link starts with http or https
        if link.startswith(('http://', 'https://')):
            try:
                if requests.get(link).history:
                    redirects += 1
            except requests.exceptions.RequestException:
                pass  # Ignore errors for invalid URLs
    return redirects / externals if externals > 0 else 0
def ratio_intErrors(Href, Link, Media, Form, CSS, Favicon):
    internals = len(Href['internals']) + len(Link['internals']) + len(Media['internals']) + len(Form['internals']) + len(CSS['internals']) + len(Favicon['internals'])
    errors = sum(1 for link in Href['internals'] + Link['internals'] + Media['internals'] + Form['internals'] + CSS['internals'] + Favicon['internals'] if requests.get(link).status_code >= 400)
    return errors / internals if internals > 0 else 0

def ratio_extErrors(Href, Link, Media, Form, CSS, Favicon):
    externals = len(Href['externals']) + len(Link['externals']) + len(Media['externals']) + len(Form['externals']) + len(CSS['externals']) + len(Favicon['externals'])
    errors = 0
    for link in Href['externals'] + Link['externals'] + Media['externals'] + Form['externals'] + CSS['externals'] + Favicon['externals']:
        # Check if the link is a valid URL for an HTTP request
        if link.startswith(('http://', 'https://')): 
            try:
                if requests.get(link, timeout=5).status_code >= 400: # Adding a timeout to prevent hanging on slow requests.
                    errors += 1
            except requests.exceptions.RequestException:
                pass  # Ignore errors for invalid URLs
    return errors / externals if externals > 0 else 0

def login_form(Form):
    return 1 if len(Form['externals']) > 0 or len(Form['null']) > 0 else 0

def external_favicon(Favicon):
    return 1 if len(Favicon['externals']) > 0 else 0

def links_in_tags(Link):
    total = len(Link['internals']) + len(Link['externals'])
    internals = len(Link['internals'])
    return internals / total if total > 0 else 0

def submit_email(Form):
    return 1 if any("mailto:" in form or "mail()" in form for form in Form['internals'] + Form['externals']) else 0

def ratio_intMedia(Media):
    total = len(Media['internals']) + len(Media['externals'])
    internals = len(Media['internals'])
    return internals / total if total > 0 else 0

def ratio_extMedia(Media):
    total = len(Media['internals']) + len(Media['externals'])
    externals = len(Media['externals'])
    return externals / total if total > 0 else 0

def sfh(hostname, Form):
    return 1 if len(Form['null']) > 0 else 0

def iframe(IFrame):
    if len(IFrame['invisible'])> 0: 
        return 1
    return 0

def popup_window(content):
    return 1 if "prompt(" in content.lower() else 0

def safe_anchor(Anchor):
    total = len(Anchor['safe']) + len(Anchor['unsafe'])
    unsafe = len(Anchor['unsafe'])
    return unsafe / total if total > 0 else 0

def onmouseover(content):
    return 1 if 'onmouseover="window.status=' in content.lower().replace(" ", "") else 0

def right_clic(content):
    return 1 if re.findall(r"event.button ?== ?2", content) else 0

def empty_title(Title):
    return 1 if not Title else 0

def domain_in_title(domain, Title):
    return 1 if domain.lower() not in Title.lower() else 0

def domain_with_copyright(domain, content):
    try:
        m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
        _copyright = content[m.span()[0]-50:m.span()[0]+50]
        return 1 if domain.lower() not in _copyright.lower() else 0
    except:
        return 0

def whois_registered_domain(domain):
    try:
        hostname = whois.whois(domain).domain_name
        if isinstance(hostname, list):
            return 1 if not any(re.search(host.lower(), domain) for host in hostname) else 0
        else:
            return 1 if not re.search(hostname.lower(), domain) else 0
    except:
        return 1

def domain_registration_length(domain):
    try:
        res = whois.whois(domain)
        expiration_date = res.expiration_date
        today = datetime.now()
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = min(expiration_date)
            return (expiration_date - today).days
        else:
            return 0
    except:
        return -1

def domain_age(domain):
    try:
        res = whois.whois(domain)
        creation_date = res.creation_date
        today = datetime.now()
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = min(creation_date)
            return (today - creation_date).days
        else:
            return 0
    except:
        return -1

def web_traffic(url):
    try:
        rank = BeautifulSoup(requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + url).content, "xml").find("REACH")['RANK']
        return int(rank)
    except:
        return 0

def dns_record(domain):
    try:
        nameservers = dns.resolver.resolve(domain, 'NS')
        return 0 if len(nameservers) > 0 else 1
    except:
        return 1

def google_index(url):
    try:
        response = requests.get("https://www.google.com/search?q=site:" + url)
        return 0 if 'did not match any documents' not in response.text else 1
    except:
        return 1

def page_rank(key, domain):
    try:
        response = requests.get(f"https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={domain}", headers={'API-OPR': key})
        result = response.json()['response'][0]['page_rank_integer']
        return result if result else 0
    except:
        return -1

