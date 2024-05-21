from flask import Flask, request, render_template
import requests
import json
import numpy as np
import pickle
from templates.features import FeatureExtraction

app = Flask(__name__)

# Define your VirusTotal API key
api_key = '3e64e77b21f33243f57c888b03054357997c40198f758a1c39fb1441c338d9c3'

# Define the API endpoints
scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
report_url = 'https://www.virustotal.com/vtapi/v2/url/report'

# Load the model from main.py
file = open("/Users/hardeesh/MAL URL Detection/website/pickle/model.pkl", "rb")
gbc = pickle.load(file)
file.close()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]

        # Part 1: Request a scan
        scan_params = {'apikey': api_key, 'url': url}
        scan_response = requests.post(scan_url, data=scan_params)
        scan_data = scan_response.json()

        # Check if the scan was successful
        if 'scan_id' in scan_data:
            scan_id = scan_data['scan_id']

            # Part 2: Get the scan report
            report_params = {'apikey': api_key, 'resource': scan_id}
            report_response = requests.get(report_url, params=report_params)
            report_data = report_response.json()

            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)

            #y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

            return render_template('index.html', url=url, report_data=report_data, xx=round(y_pro_non_phishing, 2))

    return render_template('index.html', url=None, report_data=None, xx=-1)


if __name__ == '__main__':
    app.run(debug=True, port=3000)
