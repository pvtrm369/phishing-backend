from fastapi import FastAPI, HTTPException
import joblib
import numpy as np
from urllib.parse import urlparse
from pydantic import BaseModel
import extractorFunction 
import uvicorn
import pandas as pd
import os 
from fastapi.middleware.cors import CORSMiddleware
origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:5173",
]





# Define the input data model using Pydantic
class URLRequest(BaseModel):
    url: str


model = joblib.load('DecisionTreeClassifier.joblib')


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def predict_phishing(url):
  features=extractorFunction.extract_features(url)
   
  if  features is None:
        return "Error: Unable to extract features from the URL."


  feature_names = [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq',
        'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn',
        'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
        'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
        'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension', 'nb_redirection', 'nb_external_redirection',
        'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
        'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand',
        'brand_in_subdomain', 'brand_in_path', 'suspecious_tld', 'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks',
        'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
        'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia',
        'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover', 'right_clic', 'empty_title', 'domain_in_title',
        'domain_with_copyright', 'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic', 'dns_record',
        'google_index', 'page_rank'
    ]

  df = pd.DataFrame([features], columns=feature_names)
  print(df)
  prediction = model.predict(df)
  if prediction[0] == 1:
        return "Phishing"
  else:
        return "Legitimate"
  

# API endpoint
@app.post("/predict")
def predict(url_request: URLRequest):
  
    url = url_request.url

    # Validate the URL
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    result= predict_phishing(url)

    return {"url": url, "prediction": result}

  

  

# Run the FastAPI app
if __name__ == "__main__":
   
    uvicorn.run(app, host="0.0.0.0", port=8000)