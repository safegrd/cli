package dump

import (
	"strings"
	"testing"
)

const pgDumpSample = `--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auth;


--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA public;


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;


--
-- Name: users; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.users (
    id uuid NOT NULL
);


--
-- Name: profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.profiles (
    id uuid NOT NULL
);


--
-- Name: profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profiles ADD CONSTRAINT profiles_pkey PRIMARY KEY (id);


--
-- Name: on_login; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER on_login ON login EXECUTE FUNCTION public.f();
`

// A restore of chosen schemas keeps the preamble, those schemas' objects and
// the extensions, and drops everything else, including objects in no schema.
func TestFilterSchemaSQLKeepsOnlyTheChosenSchemas(t *testing.T) {
	keep := func(s string) bool { return s == "public" }
	got := filterSchemaSQL(pgDumpSample, keep)
	for _, want := range []string{"SET client_encoding", "CREATE SCHEMA public;", "CREATE EXTENSION IF NOT EXISTS pgcrypto",
		"CREATE TABLE public.profiles", "ADD CONSTRAINT profiles_pkey"} {
		if !strings.Contains(got, want) {
			t.Errorf("dropped %q:\n%s", want, got)
		}
	}
	for _, drop := range []string{"CREATE SCHEMA auth;", "CREATE TABLE auth.users", "EVENT TRIGGER"} {
		if strings.Contains(got, drop) {
			t.Errorf("kept %q:\n%s", drop, got)
		}
	}
	// Keeping every schema still drops what belongs to the database as a
	// whole (the event trigger), and nothing else; a section with no headers
	// is returned whole.
	all := filterSchemaSQL(pgDumpSample, func(string) bool { return true })
	if strings.Contains(all, "EVENT TRIGGER") || !strings.Contains(all, "CREATE TABLE auth.users") || !strings.Contains(all, "CREATE SCHEMA auth;") {
		t.Errorf("keeping every schema:\n%s", all)
	}
	if filterSchemaSQL("SET x = 1;\n", keep) != "SET x = 1;\n" {
		t.Error("a section without headers was changed")
	}
}

func TestFilterSequenceSQLKeepsTheChosenSchemas(t *testing.T) {
	in := "-- Sequence positions, read after the rows were copied.\n" +
		"SELECT pg_catalog.setval('public.orders_id_seq', 42, true);\n" +
		"SELECT pg_catalog.setval('\"Odd Schema\".\"x\"', 7, false);\n" +
		"SELECT pg_catalog.setval('auth.refresh_tokens_id_seq', 9, true);\n"
	got := filterSequenceSQL(in, func(s string) bool { return s == "public" || s == "Odd Schema" })
	if !strings.Contains(got, "orders_id_seq") || !strings.Contains(got, "Odd Schema") || strings.Contains(got, "refresh_tokens") ||
		!strings.HasPrefix(got, "-- Sequence positions") {
		t.Errorf("filtered sequences:\n%s", got)
	}
}
