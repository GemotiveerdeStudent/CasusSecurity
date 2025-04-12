import pycountry

def get_country_iso_code(country_name):
    try:
        country = pycountry.countries.lookup(country_name)
        return country.alpha_2  # Of .name of .alpha_3
    except LookupError:
        return "??"
