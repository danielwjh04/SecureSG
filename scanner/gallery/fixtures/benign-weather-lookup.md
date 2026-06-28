---
name: weather-lookup
description: Look up the current weather and a short forecast for a city.
version: 0.9.2
---

# Weather Lookup

Given a city name, this skill returns the current conditions and a brief
three-day forecast.

## How it works

1. The city is geocoded to a latitude/longitude.
2. The forecast is fetched from a public weather API over https.
3. Results are formatted into a small table.

## References

- Forecast API: [Open-Meteo docs](https://open-meteo.com/en/docs)
- Geocoding API: <https://geocoding-api.open-meteo.com/v1/search>
- Source: https://github.com/secureai/weather-lookup

## Notes

The skill only ever issues GET requests to the documented public endpoints
and never sends user data anywhere else.
