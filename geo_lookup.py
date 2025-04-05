# geo_lookup.py
import requests

def get_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=3)
        data = response.json()
        if data['status'] == 'success':
            return {
                'ip': ip,
                'country': data.get('country', 'Onbekend'),
                'region': data.get('regionName', ''),
                'city': data.get('city', ''),
                'lat': data.get('lat'),
                'lon': data.get('lon')
            }
        else:
            return {'ip': ip, 'country': 'Onbekend'}
    except Exception as e:
        return {'ip': ip, 'country': 'Onbekend'}
