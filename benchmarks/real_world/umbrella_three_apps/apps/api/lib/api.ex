defmodule Api do
  def handle(qs), do: Core.parse(qs)
end
