"""Gazetteer detector: known place names -> LOCATION.

A small curated list of countries and major cities. Without it the heuristic NER
labels a city ("Vienna", "Berlin") as PERSON, which both mis-types the token and,
under a policy that keeps LOCATION but tokenises PERSON, over-redacts it. This is
a *recall aid for the LOCATION type*, not an exhaustive geocoder; unknown places
still fall through to NER (caught as PERSON at worst - hidden, just mislabelled).

Matching is whole-word and case-sensitive (place names are title-case), longest
name first so "New York" wins over "York".
"""

from __future__ import annotations

import re

from ..spans import EntityType, Span

_COUNTRIES = {
    "Afghanistan", "Albania", "Algeria", "Argentina", "Armenia", "Australia",
    "Austria", "Azerbaijan", "Bahrain", "Bangladesh", "Belarus", "Belgium",
    "Bolivia", "Bosnia", "Brazil", "Bulgaria", "Cambodia", "Cameroon", "Canada",
    "Chile", "China", "Colombia", "Croatia", "Cuba", "Cyprus", "Czechia",
    "Denmark", "Ecuador", "Egypt", "Estonia", "Ethiopia", "Finland", "France",
    "Georgia", "Germany", "Ghana", "Greece", "Hungary", "Iceland", "India",
    "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy", "Japan", "Jordan",
    "Kazakhstan", "Kenya", "Kuwait", "Latvia", "Lebanon", "Libya", "Lithuania",
    "Luxembourg", "Malaysia", "Malta", "Mexico", "Moldova", "Mongolia", "Morocco",
    "Nepal", "Netherlands", "Nigeria", "Norway", "Pakistan", "Panama", "Paraguay",
    "Peru", "Philippines", "Poland", "Portugal", "Qatar", "Romania", "Russia",
    "Rwanda", "Serbia", "Singapore", "Slovakia", "Slovenia", "Somalia", "Spain",
    "Sudan", "Sweden", "Switzerland", "Syria", "Taiwan", "Tanzania", "Thailand",
    "Tunisia", "Turkey", "Uganda", "Ukraine", "Uruguay", "Venezuela", "Vietnam",
    "Yemen", "Zambia", "Zimbabwe",
}
_MULTIWORD_COUNTRIES = {
    "United States", "United Kingdom", "United Arab Emirates", "South Africa",
    "South Korea", "North Korea", "New Zealand", "Saudi Arabia", "Sri Lanka",
    "Costa Rica", "Czech Republic", "Hong Kong", "El Salvador",
}
_CITIES = {
    "London", "Paris", "Berlin", "Madrid", "Rome", "Vienna", "Graz", "Linz",
    "Salzburg", "Zurich", "Zürich", "Geneva", "Munich", "Hamburg", "Frankfurt",
    "Cologne", "Amsterdam", "Rotterdam", "Brussels", "Antwerp", "Lisbon",
    "Barcelona", "Milan", "Turin", "Naples", "Venice", "Florence", "Athens",
    "Warsaw", "Krakow", "Kraków", "Prague", "Budapest", "Bucharest", "Sofia",
    "Belgrade", "Zagreb", "Ljubljana", "Bratislava", "Copenhagen", "Stockholm",
    "Oslo", "Helsinki", "Dublin", "Edinburgh", "Glasgow", "Manchester",
    "Birmingham", "Liverpool", "Lyon", "Marseille", "Nice", "Moscow",
    "Petersburg", "Kyiv", "Istanbul", "Ankara", "Cairo", "Nairobi", "Lagos",
    "Johannesburg", "Cape Town", "Casablanca", "Dubai", "Doha", "Riyadh",
    "Tehran", "Baghdad", "Jerusalem", "Beirut", "Delhi", "Mumbai", "Bangalore",
    "Karachi", "Dhaka", "Bangkok", "Jakarta", "Manila", "Singapore", "Beijing",
    "Shanghai", "Shenzhen", "Guangzhou", "Seoul", "Tokyo", "Osaka", "Kyoto",
    "Sydney", "Melbourne", "Auckland", "Toronto", "Montreal", "Vancouver",
    "Ottawa", "Chicago", "Boston", "Seattle", "Denver", "Atlanta", "Miami",
    "Dallas", "Houston", "Phoenix", "Detroit", "Philadelphia", "Washington",
    "Portland", "Anytown",
}
_MULTIWORD_CITIES = {
    "New York", "Los Angeles", "San Francisco", "San Diego", "Las Vegas",
    "New Orleans", "Cape Town", "Rio de Janeiro", "Sao Paulo", "São Paulo",
    "Buenos Aires", "Mexico City", "Hong Kong", "Kuala Lumpur", "Abu Dhabi",
    "St. Petersburg", "Tel Aviv",
}

_ALL = sorted(
    _COUNTRIES | _MULTIWORD_COUNTRIES | _CITIES | _MULTIWORD_CITIES,
    key=len, reverse=True,
)

# Single-word place names (lower-cased), for callers that must avoid treating a
# place as a person's name part - e.g. propagation must not redact the city
# "London" just because it appears as someone's middle name.
PLACE_WORDS = frozenset(
    w.lower() for w in (_COUNTRIES | _CITIES) if " " not in w
)
_RE = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(p) for p in _ALL) + r")(?!\w)")


def detect(text: str) -> list[Span]:
    """Return LOCATION spans for known place names in ``text``."""
    # Confidence sits just above PERSON (0.5) so a bare city wins the "Berlin"
    # vs PERSON tie, but below ORGANIZATION (0.55) so a city inside an org name
    # ("Regional Court Graz") doesn't fragment the org in overlap resolution.
    return [Span(m.start(), m.end(), EntityType.LOCATION, m.group(0), 0.52, "gazetteer")
            for m in _RE.finditer(text)]
