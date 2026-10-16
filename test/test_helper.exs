ExUnit.start()

Mox.defmock(TestHTTPClient, for: Supabase.Fetcher.Adapter)

# Set once for the whole suite and never deleted: per-module swapping of this
# key under `async: true` races (a module's teardown deletes the env while
# another module's tests still need the mock, so requests hit the real Finch).
Application.put_env(:supabase_auth, :http_client, TestHTTPClient)
