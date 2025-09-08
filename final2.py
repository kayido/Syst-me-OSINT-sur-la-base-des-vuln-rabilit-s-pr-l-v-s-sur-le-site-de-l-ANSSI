import os
import json
import re
import requests
import pandas as pd
import feedparser
import smtplib
from email.mime.text import MIMEText
import time


folder = "data_pour_TD_final"
TIME_SLEEP = 2
def list_files_in_directory(directory_path):
    try:
        if not os.path.isdir(directory_path):
            return f"Le dossier '{directory_path}' n'existe pas."

        files = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]        
        return files
    
    except Exception as e:
        return f"Une erreur est survenue : {e}"


def extract_json(foler_name, infos) :
    dossier = f"{folder}/{foler_name}"
    fichiers = list_files_in_directory(dossier)
    print("en cours")
    #acceder à une alerte
    i = 0
    for alerte_id in fichiers : 
        with open(rf"{folder}/{foler_name}/"+alerte_id, 'r') as f:
            data=json.load(f)
        
        ref_cves=list(data["cves"])
        title = data['title']
        type = "alerte" if foler_name == "alertes" else "Avis"
        try :
            url = f"https://www.cert.ssi.gouv.fr/{type}/"+alerte_id+"/"
            date =  data['vendor_advisories'][1]["published_at"]
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_list = list(set(re.findall(cve_pattern, str(data))))
            infos[alerte_id] = {
                'title' : title,
                "CVE" : cve_list,
                "URL" : url,
                "date" : date,
                "type" : type
            }
        except :
            pass


def extract_CVE(infos):
    cves = []
    for i in infos :
        for cve in infos[i]['CVE'] :
            if cve not in cves :
                cves.append(cve)
    
    return cves


def classifier_cvss(score):
    score = float(score)
    if score < 0 or score > 10:
        return None
    elif score <= 3:
        return "LOW"
    elif score <= 6:
        return "MEDIUM"
    elif score <= 8:
        return "HIGH"
    else:
        return "CRITICAL"


def extract_addictional_information_CVE(infos) : 
    c_cves = {}
    cves = extract_CVE(infos)
    dossier = f"{folder}/mitre"
    i = 0
    for cve_id in cves:
        try :
            with open(rf"{folder}/mitre/"+cve_id, 'r') as f:
                data=json.load(f)
            
            # Extraire la description
            try :
                description = data["containers"]["cna"]["descriptions"][0]["value"]
            except KeyError: 
                description = "pas de description"
            # Extraire le score CVSS
            #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
            #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
                        
            try :
                cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
                base_severity =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]
            except KeyError:
                try : 
                    cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
                    base_severity =data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseSeverity"]
                except :
                    cvss_score = None
                    base_severity = None
            
            cwe = "Non disponible"
            cwe_desc="Non disponible"
            try :
                problemtype = data["containers"]["cna"].get("problemTypes", {})
            except KeyError: 
                problemtype = ""
            
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
            # Extraire les produits affectés

            try :
                affected = data["containers"]["cna"]["affected"]
                for product in affected:
                    vendor = product["vendor"]
                    product_name = product["product"]
                    versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                
            except KeyError: 
                vendor = "n/a"
                product_name = "n/a"
                versions = []
                affected = ""
        
            with open(rf"{folder}/first/"+cve_id, 'r') as f:
                data=json.load(f)
                        
            # Extraire le score EPSS
            epss_data = data.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]    
            else:
                print(f"Aucun score EPSS trouvé pour {cve_id}")
            
            c_cves[cve_id] = {
                "description" : description,
                "CVSS" : cvss_score,
                "EPSS" : epss_score,
                "version" : versions,
                "product" : product_name,
                "editeur" : vendor,
                "CWE" : cwe,
                "base_severity" : base_severity if base_severity is not None else classifier_cvss(epss_score)
            }
            if i == 500 :
                break

            i += 1
        except FileNotFoundError  :
            print("fichier non trouvé")
    
    return c_cves
    

def construct_dataframe(infos):
    c_cves = extract_addictional_information_CVE(infos)
    print("en cours")
    data = {}
    i = 0
    for anssi in infos.keys() :
        for cve in infos[anssi]['CVE'] :
            try : 
                data[anssi] = {
                    'title' : infos[anssi]["title"],
                    'date' :  infos[anssi]["date"],
                    'type' : infos[anssi]["type"],
                    'CVE' : cve,
                    'lien' :  infos[anssi]["URL"],
                    'description' :  c_cves[cve]["description"],
                    "CVSS" : c_cves[cve]["CVSS"],
                    "EPSS" : c_cves[cve]["EPSS"],
                    "version" : c_cves[cve]["version"],
                    "product" : c_cves[cve]["product"],
                    "editeur" : c_cves[cve]["editeur"],
                    "CWE" : c_cves[cve]["CWE"],
                    "base_severity" : c_cves[cve]["base_severity"]
                }
                if i == 200 :
                    break
                print(i)
                i += 1
            except :
                print("Données Incomplet")

    df = pd.DataFrame(data)
    df = df.T
    print(df)

    df.to_csv("data.csv", index=True, encoding='utf-8')


    

def extract_data_api() :
    
    import requests

    apis = {
        "Avis" : "https://www.cert.ssi.gouv.fr/avis/feed",
        "Alerte" : "https://www.cert.ssi.gouv.fr/alertes/feed"
    }
    IDbulletinsAnssi = []
    links = []
    ANSSIS = {}
    i = 0
    for type , url in apis.items() :
        rss_feed = feedparser.parse(url)       
        for entry in rss_feed.entries:

            IDbulletinsAnssi.append(entry.link.split("/")[4])
            links.append(entry.link)
            
            ANSSIS[entry.link.split("/")[4]] = {
                "title" : entry.title,
                "type" : type,
                "Date" : entry.published,
                "lien" : entry.link,
                "Description" : entry.description,
            }
            if i == 50 :
                break

            i += 1
            #time.sleep(TIME_SLEEP)

    urls = [url+"json/" for url in links]
    infos = {}
    for url in urls :
        print(url)
        response = requests.get(url)
        data = response.json()
        #Extraction des CVE reference dans la clé cves du dict data
        ref_cves=list(data["cves"])
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))
        #print("CVE trouvés :", cve_list)
        infos[url.split("/")[4]] = {
            "CVE" : cve_list,
            "URL" : url
        }

    cves = []
    for i in infos :
        for cve in infos[i]['CVE'] :
            if cve not in cves :
                cves.append(cve)

    c_cves = {}
    i = 0
    for cve_id in cves :
        try : 
            url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response = requests.get(url)
            data = response.json()
            # Extraire la description
            description = data["containers"]["cna"]["descriptions"][0]["value"]
            try :
                cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
                base_severity =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]

            except KeyError:
                try : 
                    cvss_score =data["containers"]["cna"]["metrics"][1]["cvssV3_0"]["baseScore"]
                    base_severity =data["containers"]["cna"]["metrics"][1]["cvssV3_0"]["baseSeverity"]
                except :
                    cvss_score = None
                    base_severity = None
            
            cwe = "Non disponible"
            cwe_desc="Non disponible"
            problemtype = data["containers"]["cna"].get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
            # Extraire les produits affectés
            affected = data["containers"]["cna"]["affected"]
            for product in affected:                
                vendor = product["vendor"]
                product_name = product["product"]
                versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                #print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
            
            # URL de l'API EPSS pour récupérer la probabilité d'exploitation
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            # Requête GET pour récupérer les données JSON
            response = requests.get(url)
            data = response.json()
            # Extraire le score EPSS
            epss_data = data.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]
            else:
                print(f"Aucun score EPSS trouvé pour {cve_id}")
        
            c_cves[cve_id] = {
                "CVSS" : cvss_score,
                "EPSS" : epss_score,
                "version" : versions,
                "product" : product_name,
                "editeur" : vendor,
                "CWE" : cwe,
                "base_severity" : base_severity
            }
            if i == 200:
                break
            i += 1
            print(i)
        except :
            print("Exception retournée du a un attribut manquant dans la données recupérées")

        #time.sleep(TIME_SLEEP)

    #etape 4 :
    data = {}
    i = 0
    for anssi in ANSSIS.keys() :
        for cve in infos[anssi]['CVE'] :
            try :
                data[anssi] = {
                    'title' : ANSSIS[anssi]["title"],
                    'date' :  ANSSIS[anssi]["Date"],
                    'type' :  ANSSIS[anssi]["type"],
                    'CVE' : cve,
                    'lien' :  ANSSIS[anssi]["lien"],
                    'description' :  ANSSIS[anssi]["Description"],
                    "CVSS" : c_cves[cve]["CVSS"],
                    "EPSS" : c_cves[cve]["EPSS"],
                    "version" : c_cves[cve]["version"],
                    "product" : c_cves[cve]["product"],
                    "editeur" : c_cves[cve]["editeur"],
                    "CWE" : c_cves[cve]["CWE"],
                    "base_severity" : c_cves[cve]["base_severity"]
                }
            except KeyError: 
                continue
            if i == 100 :
                break
            i += 1
            
    df = pd.DataFrame(data)
    df = df.T

    df.to_csv("data_api.csv",  index=True, encoding='utf-8')


def send_email(to_email, subject, body):
    from_email = "your_email"
    password = "your_password"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()
    print("message envoyé")


def manage_mailing ():
    df_user = pd.read_csv("users.csv")
    df = pd.read_csv("data_api.csv")
    for i in range(0, df.shape[0]) :
        editors = df.loc[i]["editeur"]
        print(editors)
        for j in range(df_user.shape[0]) :
            print(df_user.loc[j]["id"])
            logiciels = df_user.loc[j]["logiciels"]
            
            for logiciel in json.loads(logiciels):
                if logiciel == editors :
                    if df.loc[i]["CVE"] not in df_user.loc[j]["cves"] :
                        
                        send_email(df_user.loc[j]["email"], f"{df.loc[i]["type"]} detecté", f"{df.loc[i]["type"]} detecté chez un produit de {logiciel} \n  {df.loc[i]["description"]} \n\n link : {df.loc[i]["lien"]}")
                        vulnerabilite = df.loc[i]["CVE"]
                        vulnerabilite = str(vulnerabilite)
                        update_user_cve(df_user.loc[j]["id"], vulnerabilite, filename="users.csv")

                    else :
                        print("Alerte déja envoyé")  
                

def update_user_cve(user_id, cve_value, filename="users.csv") : 
    try:
        # Charger le fichier CSV avec pandas
        df = pd.read_csv(filename)
    except FileNotFoundError:
        print(f"Erreur : Fichier {filename} introuvable")
        return
    print(df)

    # Trouver l'index de l'utilisateur
    user_index = df[df['id'] == user_id].index
    if len(user_index) > 0:
        idx = user_index[0]        
        # Gérer les valeurs existantes ou vides
        current_cves = df.at[idx, 'cves']
        
        if pd.isna(current_cves) or current_cves == '':
            df.at[idx, 'cves'] = f"[{cve_value}]"
        else:
            # Nettoyer les crochets existants
            cleaned = current_cves.strip('[]')
            if cleaned:
                df.at[idx, 'cves'] = f"[{cleaned},{cve_value}]"
            else:
                df.at[idx, 'cves'] = f"[{cve_value}]"
        
        # Sauvegarder les modifications
        print(df)
        df.to_csv(filename, header=False, index=False)
        print(f"Utilisateur {user_id} mis à jour avec la CVE {cve_value}")
    else : 
        print(f"Utilisateur {user_id} Non trouvée")

    print(df)
    df.to_csv(filename, index=False)
    print(f"Utilisateur {user_id} mis à jour avec la CVE {cve_value}")


def traitement() :
    while True :
        print("Recuperation des données via API \n\n. Pour reduire le temps excutions du programmation, nous avons autoritsé extraction de 10 bullentins ANSSI du flux RSS")
        print("Pour les raisons de test, j'ai mise enlévé la pause entre 02 requette http")
        # extract_data_api()
        print("Traitement extrait, donné extrait dans data_api.csv")
        manage_mailing()
        print("Veuillez patientiez 30 min suppplementaire pour le nouveau traitement")
        time.sleep(1800)


if __name__ == "__main__":

    # print("Recuperation des données via API \n\n. Pour reduire le temps excutions du programmation, nous avons autoritsé extraction de 10 bullentins ANSSI du flux RSS")
    # print("Pour les raisons de test, j'ai mise enlévé la pause entre 02 requette http")
    # extract_data_api()
    # print("Traitement extrait, donné extrait dans data_api.csv")

    # infos = {}
    # print("\n\n Creation de historique de données via le dossier data_pour_TD_final")
    # extract_json("alertes",infos)
    # extract_json("Avis", infos)
    # extract_CVE(infos)
    # construct_dataframe(infos)

    traitement()
