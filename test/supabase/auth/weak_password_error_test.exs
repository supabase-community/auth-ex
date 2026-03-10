defmodule Supabase.Auth.WeakPasswordErrorTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.WeakPasswordError

  describe "maybe_enrich/1" do
    test "enriches error when resp_body has weak_password reasons" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        message: "Unprocessable Entity",
        service: :auth,
        metadata: %{
          resp_body: %{
            "error_code" => "weak_password",
            "msg" => "Password too short",
            "weak_password" => %{"reasons" => ["length"]}
          }
        }
      }

      enriched = WeakPasswordError.maybe_enrich(error)

      assert %Supabase.Error{} = enriched
      assert enriched.metadata.weak_password_reasons == [:length]
      assert enriched.message == "Password too short"
    end

    test "enriches error with multiple reasons" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        message: "Unprocessable Entity",
        service: :auth,
        metadata: %{
          resp_body: %{
            "error_code" => "weak_password",
            "msg" => "Password is not strong enough",
            "weak_password" => %{"reasons" => ["length", "characters", "pwned"]}
          }
        }
      }

      enriched = WeakPasswordError.maybe_enrich(error)

      assert enriched.metadata.weak_password_reasons == [:length, :characters, :pwned]
    end

    test "passes through non-weak-password errors unchanged" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        message: "Validation failed",
        service: :auth,
        metadata: %{
          resp_body: %{"error_code" => "validation_failed", "msg" => "Invalid email"}
        }
      }

      assert WeakPasswordError.maybe_enrich(error) == error
    end

    test "passes through errors without resp_body" do
      error = %Supabase.Error{
        code: :unexpected,
        message: "Unexpected",
        service: :auth,
        metadata: %{}
      }

      assert WeakPasswordError.maybe_enrich(error) == error
    end

    test "passes through errors with non-map resp_body" do
      error = %Supabase.Error{
        code: :unexpected,
        message: "Unexpected",
        service: :auth,
        metadata: %{resp_body: "some string"}
      }

      assert WeakPasswordError.maybe_enrich(error) == error
    end

    test "enriches when error_code is weak_password but reasons are empty" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        message: "Unprocessable Entity",
        service: :auth,
        metadata: %{
          resp_body: %{
            "error_code" => "weak_password",
            "msg" => "Weak password"
          }
        }
      }

      enriched = WeakPasswordError.maybe_enrich(error)

      assert enriched.metadata.weak_password_reasons == []
      assert enriched.message == "Weak password"
    end

    test "filters unknown reasons" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        message: "Unprocessable Entity",
        service: :auth,
        metadata: %{
          resp_body: %{
            "error_code" => "weak_password",
            "msg" => "Weak password",
            "weak_password" => %{"reasons" => ["length", "unknown_reason"]}
          }
        }
      }

      enriched = WeakPasswordError.maybe_enrich(error)

      assert enriched.metadata.weak_password_reasons == [:length]
    end
  end

  describe "weak_password?/1" do
    test "returns true for enriched weak password errors" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        metadata: %{weak_password_reasons: [:length]}
      }

      assert WeakPasswordError.weak_password?(error)
    end

    test "returns false for regular errors" do
      error = %Supabase.Error{code: :unprocessable_entity, metadata: %{}}

      refute WeakPasswordError.weak_password?(error)
    end

    test "returns false for empty reasons list" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        metadata: %{weak_password_reasons: []}
      }

      refute WeakPasswordError.weak_password?(error)
    end
  end

  describe "reasons/1" do
    test "extracts reasons from enriched error" do
      error = %Supabase.Error{
        code: :unprocessable_entity,
        metadata: %{weak_password_reasons: [:length, :characters]}
      }

      assert WeakPasswordError.reasons(error) == [:length, :characters]
    end

    test "returns empty list for non-weak-password errors" do
      error = %Supabase.Error{code: :unprocessable_entity, metadata: %{}}

      assert WeakPasswordError.reasons(error) == []
    end
  end
end
