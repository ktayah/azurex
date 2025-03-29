defmodule Azurex.Authorization.Utils do
  def put_standard_headers(request, content_type, date) do
    headers =
      if content_type,
        do: [{"content-type", content_type} | request.headers],
        else: request.headers

    headers = [
      {"x-ms-version", "2023-01-03"},
      {"x-ms-date", format_date(date)}
      | headers
    ]

    struct(request, headers: headers)
  end

  def format_date(%DateTime{zone_abbr: "UTC"} = date_time) do
    Calendar.strftime(date_time, "%a, %d %b %Y %H:%M:%S GMT")
  end
end
