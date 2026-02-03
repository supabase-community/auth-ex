[
  # MFA functions: response.body is decoded to map at runtime by JSONDecoder
  # but Dialyzer sees it as iodata | {:stream, _} | nil
  {"lib/supabase/auth/mfa.ex", :pattern_match},
  {"lib/supabase/auth/mfa.ex", :no_return},
  {"lib/supabase/auth/mfa.ex", :unused_fun},
  {"lib/supabase/auth.ex", :pattern_match}
]
