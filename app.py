from flask import Flask, render_template, request, jsonify, Response
import dns.resolver
import requests
import json

app = Flask(__name__)

# Cloud Service Fingerprints for Subdomain Takeover Detection
CLOUD_FINGERPRINTS = {
    "GitHub Pages": {
        "cname": ["github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root domain support, see"],
        "poc": "Claim the custom domain in your GitHub repository settings under GitHub Pages."
    },
    "AWS S3 Bucket": {
        "cname": ["s3.amazonaws.com"],
        "fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
        "poc": "Create an AWS S3 bucket with the exact name of the vulnerable domain."
    },
    "Heroku": {
        "cname": ["herokuapp.com"],
        "fingerprints": ["Heroku | No such app", "there is no app configured at that hostname"],
        "poc": "Add the domain as a custom domain to your Heroku application."
    },
    "Shopify": {
        "cname": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable.", "Only one Shopify store can be attached"],
        "poc": "Add the domain as a custom domain in your Shopify store admin panel."
    },
    "WordPress.com": {
        "cname": ["wordpress.com"],
        "fingerprints": ["Do you want to buy this domain?", "is not claimed"],
        "poc": "Claim the mapped domain within your WordPress.com account settings."
    },
    "Tumblr": {
        "cname": ["tumblr.com"],
        "fingerprints": ["Whatever you were looking for doesn't here.", "There's nothing here."],
        "poc": "Point a custom domain in your Tumblr blog settings."
    }
}

def check_subdomain_takeover(domain):
    results = []
    # Clean up input
    domain = domain.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")
    
    subdomains_to_check = [
        domain,
        f"blog.{domain}",
        f"dev.{domain}",
        f"test.{domain}",
        f"shop.{domain}",
        f"app.{domain}",
        f"staging.{domain}",
        f"api.{domain}"
    ]

    for sub in subdomains_to_check:
        status = "NOT VULNERABLE"
        cname_found = "None"
        service_detected = "N/A"
        poc_guide = "No dangling CNAME detected."
        color = "#3fb950" # Green

        try:
            # Query CNAME records
            answers = dns.resolver.resolve(sub, 'CNAME')
            for rdata in answers:
                cname_found = str(rdata.target).rstrip('.')
                
                # Check CNAME against cloud fingerprints
                for provider, data in CLOUD_FINGERPRINTS.items():
                    if any(provider_cname in cname_found for provider_cname in data["cname"]):
                        service_detected = provider
                        
                        # Verify live HTTP response for fingerprint matches
                        try:
                            http_resp = requests.get(f"http://{sub}", timeout=3, headers={"User-Agent": "Mozilla/5.0"})
                            resp_text = http_resp.text
                        except Exception:
                            resp_text = ""

                        # Match signature error strings
                        if any(fp in resp_text for fp in data["fingerprints"]) or resp_text == "":
                            status = "TAKEOVER POSSIBLE"
                            color = "#f85149" # Red
                            poc_guide = data["poc"]
                        else:
                            status = "CNAME DETECTED (SECURE)"
                            color = "#d29922" # Yellow
                            poc_guide = f"Dangling CNAME points to {cname_found}, but the service appears actively configured."

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            pass

        results.append({
            "subdomain": sub,
            "cname": cname_found,
            "service": service_detected,
            "status": status,
            "color": color,
            "poc": poc_guide
        })

    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    scan_results = None
    target_domain = ""
    if request.method == 'POST':
        target_domain = request.form.get('domain', '')
        if target_domain:
            scan_results = check_subdomain_takeover(target_domain)

    return render_template('index.html', results=scan_results, domain=target_domain)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
