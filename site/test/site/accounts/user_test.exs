defmodule Site.Accounts.UserTest do
  use ExUnit.Case, async: true
  alias Site.Accounts.User
  alias Site.Products

  setup do
    # Mock de produtos
    products = [
      %{
        "id" => "1a2b3c4d-5678-90ab-cdef-1234567890ab",
        "name" => "Produto A",
        "price" => 19.99,
        "tags" => ["tag1", "tag2"]
      },
      %{
        "id" => "2b3c4d5e-6789-01bc-defg-2345678901bc",
        "name" => "Produto B",
        "price" => 29.99,
        "tags" => ["tag3", "tag4"]
      }
    ]

    {:ok, products: products}
  end

  test "adiciona um produto ao basket", %{products: products} do
    user = %User{basket: []}
    product_id = products |> hd() |> Map.get("id")

    changeset = User.add_to_basket(user, product_id, 2)
    IO.inspect(changeset.changes.basket, label: "Basket após adicionar")

    assert changeset.changes.basket == [%{"id" => product_id, "quantity" => 2}]
  end

  test "remove um produto do basket", %{products: products} do
    product_id = products |> hd() |> Map.get("id")
    user = %User{basket: [%{"id" => product_id, "quantity" => 2}]}

    changeset = User.remove_from_basket(user, product_id)
    assert changeset.changes.basket == []
  end

  test "lista os produtos no basket", %{products: products} do
    product_id = products |> hd() |> Map.get("id")
    user = %User{basket: [%{"id" => product_id, "quantity" => 2}]}

    basket = User.list_basket(user)
    assert length(basket) == 1
    assert hd(basket)["id"] == product_id
    assert hd(basket)["quantity"] == 2
  end
end
