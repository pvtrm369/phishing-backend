from urllib.parse import urljoin 
import re
import requests
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
import dns.resolver
from datetime import datetime
import featureExtractor as fe

def extract_features(url, status=None):
   
    parsed = urlparse(url)
    scheme = parsed.scheme
    hostname = parsed.hostname
    path = parsed.path
    query = parsed.query

    
    extracted_domain = tldextract.extract(url)
    domain = extracted_domain.domain + '.' + extracted_domain.suffix
    subdomain = extracted_domain.subdomain

  
    words_raw = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", url.lower())
    words_raw = list(filter(None, words_raw))

    # Fetch the webpage content
    try:
        response = requests.get(url, timeout=10)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

    # Initialize dictionaries for hyperlinks, media, forms, etc.
    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}
    IFrame = {'visible': [], 'invisible': [], 'null': []}
    Anchor = {'safe': [], 'unsafe': [], 'null': []}

    # Extract data from the webpage
    for href in soup.find_all('a', href=True):
        link = href['href']
        if not link.startswith(('http://', 'https://')):
            # Convert relative URL to absolute URL
            link = urljoin(url, link)
        if hostname in link or domain in link:
            Href['internals'].append(link)
        else:
            Href['externals'].append(link)

    for img in soup.find_all('img', src=True):
        link = img['src']
        if not link.startswith(('http://', 'https://')):
            # Convert relative URL to absolute URL
            link = urljoin(url, link)
        if hostname in link or domain in link:
            Media['internals'].append(link)
        else:
            Media['externals'].append(link)

    for form in soup.find_all('form', action=True):
        link = form['action']
        if not link.startswith(('http://', 'https://')):
            # Convert relative URL to absolute URL
            link = urljoin(url, link)
        if hostname in link or domain in link:
            Form['internals'].append(link)
        else:
            Form['externals'].append(link)

    for link in soup.find_all('link', href=True):
        link = link['href']
        if not link.startswith(('http://', 'https://')):
            # Convert relative URL to absolute URL
            link = urljoin(url, link)
        if hostname in link or domain in link:
            CSS['internals'].append(link)
        else:
            CSS['externals'].append(link)

    for iframe_tag in soup.find_all('iframe', src=True):
        link = iframe_tag['src']
        if not link.startswith(('http://', 'https://')):
            # Convert relative URL to absolute URL 
            link = urljoin(url, link)
        if hostname in link or domain in link:
            IFrame['visible'].append(link)
        else:
            IFrame['invisible'].append(link)


    # Extract features (rest of the code remains the same)
    features = [
        fe.url_length(url),
        len(hostname) if hostname else 0,
        fe.having_ip_address(url),
        fe.count_dots(url),
         fe.count_hyphens(url),
         fe.count_at(url),
         fe.count_qm(url),
         fe.count_and(url),
         fe.count_or(url),
         fe.count_eq(url),
         fe.count_underscore(url),
         fe.count_tilde(url),
         fe.count_percent(url),
         fe.count_slash(url),
         fe.count_star(url),
         fe.count_colon(url),
         fe.count_comma(url),
         fe.count_semicolumn(url),
         fe.count_dollar(url),
         fe.count_space(url),
         fe.count_www(words_raw),
         fe.count_com(words_raw),
         fe.count_dslash(url),
         fe.http_in_path(path),
         fe.https_token(scheme),
         fe.ratio_digits(url),
         fe.ratio_digits(hostname) if hostname else 0,
         fe.punycode(url),
         fe.port(url),
         fe.tld_in_path(extracted_domain.suffix, path),
         fe.tld_in_subdomain(extracted_domain.suffix, subdomain),
         fe.abnormal_subdomain(url),
         fe.count_subdomain(url),
         fe.prefix_suffix(url),
         fe.random_domain(domain),
         fe.shortening_service(url),
         fe.path_extension(path),
         fe.count_redirection(response),
         fe.count_external_redirection(response, domain),
         fe.length_words_raw(words_raw),
         fe.char_repeat(words_raw),
         fe.shortest_words_raw(words_raw),
         len(extracted_domain.domain),
         len(path.split('/')[-1]),
         fe.longest_words_raw(words_raw),
         len(extracted_domain.domain),
        len(path.split('/')[-1]),
         fe.avg_words_raw(words_raw),
        len(extracted_domain.domain) / len(words_raw) if words_raw else 0,
        len(path.split('/')[-1]) / len(words_raw) if words_raw else 0,
         fe.phish_hints(url),
         fe.domain_in_brand(extracted_domain.domain),
         fe.brand_in_subdomain(extracted_domain.domain, subdomain),
         fe.brand_in_path(extracted_domain.domain, path),
         fe.suspecious_tld(extracted_domain.suffix),
         fe.statistical_report(url, domain),
         fe.nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
         fe.ratio_intHyperlinks(Href, Link, Media, Form, CSS, Favicon),
         fe.ratio_extHyperlinks(Href, Link, Media, Form, CSS, Favicon),
         fe.ratio_nullHyperlinks(Href, Link, Media, Form, CSS, Favicon),
         fe.nb_extCSS(CSS),
         fe.ratio_intRedirection(Href, Link, Media, Form, CSS, Favicon),
         fe.ratio_extRedirection(Href, Link, Media, Form, CSS, Favicon),
         fe.ratio_intErrors(Href, Link, Media, Form, CSS, Favicon),
         fe.ratio_extErrors(Href, Link, Media, Form, CSS, Favicon),
         fe.login_form(Form),
         fe.external_favicon(Favicon),
         fe.links_in_tags(Link),
         fe.submit_email(Form),
         fe.ratio_intMedia(Media),
         fe.ratio_extMedia(Media),
         fe.sfh(hostname, Form),
         fe.iframe(IFrame),
         fe.popup_window(content),
         fe.safe_anchor(Anchor),
         fe.onmouseover(content),
         fe.right_clic(content),
         fe.empty_title(soup.title.string if soup.title else ''),
         fe.domain_in_title(extracted_domain.domain, soup.title.string if soup.title else ''),
         fe.domain_with_copyright(extracted_domain.domain, content),
         fe.whois_registered_domain(domain),
         fe.domain_registration_length(domain),
         fe.domain_age(domain),
         fe.web_traffic(url),
         fe.dns_record(domain),
         fe.google_index(url),
         fe.page_rank('84ko04o4g4gswgogwc8ow4kggw4w00so4kogcs40', domain)
    ]

    
    if status is not None:
        features.append(status)

    return features