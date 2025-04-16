defmodule Site.Repo.Migrations.AddBasketToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add(:basket, {:array, :map}, default: [])
    end
  end
end
