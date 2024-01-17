import pickle
import project
import pandas as pd
from flask import Flask,request,redirect,render_template,url_for
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import socket
import json
import requests

model=pickle.load(open("website-model.sav","rb"))


app = Flask(__name__)
state=0


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/form',methods=['POST','GET'])
def form():
    if(request.method=='POST'):
      url=request.form['url_name']
      if(not url.isnumeric()):
        li=project.featureExtraction(url)
        li_df=pd.DataFrame([li],columns=project.feature_names)
        ar = model.predict(li_df)
        with virustotal_python.Virustotal("c5977ace1e268df454c6afe2b86b454ca3d81bd25ea4a585bca45745df3bd049") as vtotal:
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
        domain=url.split('https://www.')[1]
        ip=socket.gethostbyname(domain)
        remark=''
        if(data=='Secured and Verified'):
          remark=""
        elif(data=='Legitimate Website'):
          remark=""
        else:
          remark=""
        
      else:
          state=2
          class IPQS:
            key =  'njXPgIGXkrxFfdeKFKYDvlhSjnweua1D'
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

if __name__ == '__main__':
    app.run(debug=True)


