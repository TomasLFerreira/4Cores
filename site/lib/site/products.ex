defmodule Site.Products do
  @moduledoc """
  Módulo para carregar e validar produtos.
  """

  @products_file Path.join(:code.priv_dir(:site), "products.json")

  @doc """
  Carrega os produtos do arquivo JSON.
  """
  def load_products do
    @products_file
    |> File.read!()
    |> Jason.decode!()
  end

  @doc """
  Verifica se um produto existe pelo ID.
  """
  def product_exists?(product_id) do
    load_products()
    |> Enum.any?(fn product -> product["id"] == product_id end)
  end

  @doc """
  Retorna os detalhes de um produto pelo ID.
  """
  def get_product(product_id) do
    load_products()
    |> Enum.find(fn product -> product["id"] == product_id end)
  end
end
