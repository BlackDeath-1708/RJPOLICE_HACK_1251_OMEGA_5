import pickle
import project
import pandas as pd
from flask import Flask,request,redirect,render_template,url_for
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
from urllib.parse import urlparse
import socket
import json
import requests

model=pickle.load(open("website-model.sav","rb"))


app = Flask(__name__)
state=0
report=''

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/form',methods=['POST','GET'])
def form():
    global report
    if(request.method=='POST'):
      url=request.form['url_name']
      if(not url.isnumeric()):
        li=project.featureExtraction(url)
        li_df=pd.DataFrame([li],columns=project.feature_names)
        ar = model.predict(li_df)
        with virustotal_python.Virustotal("1c921e768b650441233fc5b7e190f39d4d15a653619ce71cb78dbfe06d21771e") as vtotal:
            try:
                resp = vtotal.request("urls", data={"url": url}, method="POST")
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
            except virustotal_python.VirustotalError as err:
                print(f"Failed to send URL: {url} for analysis and get the report: {err}")
        if (report.data['attributes']['last_analysis_stats']['harmless']>0 and report.data['attributes']['last_analysis_stats']['malicious']==0):
          n=0
        elif(report.data['attributes']['last_analysis_stats']['malicious']>0):
          n=1
        for i in ar:
          if(i==0 and n==0):
            data = ("Secured and Verified")
          elif(i==1 and n==0):
            data = ("Legitimate Website")
          elif (i==1 and n==1):
            data = ("Phishing")
        state=1
        domain=urlparse(url).netloc
        try: 
           ip=socket.gethostbyname(domain)
        except:
           ip="Not Found"
        remark=''
        
      else:
          state=2
          class IPQS:
            key =  'xaZHdfr2WMVOUbeCxl3S6eOGB9ycc4Yd'
            def phone_number_api(self, phonenumber: str, vars: dict = {}) -> dict:
              url = 'https://www.ipqualityscore.com/api/json/phone/%s/%s' %(self.key, phonenumber)
              x = requests.get(url, params = vars)
              return (json.loads(x.text))
          if __name__ == "__main__":
              phone = url
              countries = {'US', 'CA'}
              additional_params = {
                'country' : countries
              }
              ipqs = IPQS()
              result  = ipqs.phone_number_api(phone, additional_params)
              data=result['message']
              remark= "Yes" if result['spammer'] else "No"
              domain= "Yes" if result['recent_abuse'] else "No"
              ip=result['fraud_score']
      return render_template('index.html',state=state,data=data,url=url,domain=domain,ip=ip,remark=remark)          


@app.route('/cyber_laws')
def cyber_laws():
      return render_template('cyber_law.html')

@app.route('/more_details/<string:url>')
def more_details(url):
      with virustotal_python.Virustotal("1c921e768b650441233fc5b7e190f39d4d15a653619ce71cb78dbfe06d21771e") as vtotal:
            try:
                resp = vtotal.request("urls", data={"url": url}, method="POST")
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
            except virustotal_python.VirustotalError as err:
                print(f"Failed to send URL: {url} for analysis and get the report: {err}")
      data=[]
      data.append(report.data['attributes']['last_analysis_results']['ESTsecurity']['category'])
      data.append(report.data['attributes']['last_analysis_results']['Google Safebrowsing']['category'])
      data.append(report.data['attributes']['last_analysis_results']['Juniper Networks']['category'])
      data.append(report.data['attributes']['last_analysis_results']['K7AntiVirus']['category'])
      data.append(report.data['attributes']['last_analysis_results']['Kaspersky']['category'])
      data.append(report.data['attributes']['last_analysis_results']['PhishLabs']['category'])
      data.append(report.data['attributes']['last_analysis_results']['Netcraft']['category'])
      data.append(report.data['attributes']['last_analysis_results']['Phishtank']['category'])
      data.append(report.data['attributes']['last_analysis_results']['Quick Heal']['category'])
      data.append(report.data['attributes']['last_analysis_results']['URLQuery']['category'])
      return render_template('more_details.html',data=data)

if __name__ == '__main__':
    app.run(debug=True)


