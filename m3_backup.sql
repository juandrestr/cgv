--
-- PostgreSQL database dump
--

\restrict IznG4Fky7IqJlFJLE0GaatopwchKeYw5zPTdwwa5IBkXbXoeLFqxrY2PuhZLQlN

-- Dumped from database version 16.10 (Debian 16.10-1.pgdg13+1)
-- Dumped by pg_dump version 16.10 (Debian 16.10-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: cgv
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO cgv;

--
-- Name: notes; Type: TABLE; Schema: public; Owner: cgv
--

CREATE TABLE public.notes (
    id integer NOT NULL,
    msg character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.notes OWNER TO cgv;

--
-- Name: notes_id_seq; Type: SEQUENCE; Schema: public; Owner: cgv
--

CREATE SEQUENCE public.notes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notes_id_seq OWNER TO cgv;

--
-- Name: notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cgv
--

ALTER SEQUENCE public.notes_id_seq OWNED BY public.notes.id;


--
-- Name: notes id; Type: DEFAULT; Schema: public; Owner: cgv
--

ALTER TABLE ONLY public.notes ALTER COLUMN id SET DEFAULT nextval('public.notes_id_seq'::regclass);


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: cgv
--

COPY public.alembic_version (version_num) FROM stdin;
1c6efb76704b
\.


--
-- Data for Name: notes; Type: TABLE DATA; Schema: public; Owner: cgv
--

COPY public.notes (id, msg, created_at) FROM stdin;
1	hello from API	2025-10-05 19:16:45.705465+00
2	second note	2025-10-05 19:18:57.07863+00
3	nano saved version works	2025-10-05 19:29:01.761678+00
4	ping	2025-10-05 21:11:51.988963+00
5	hello	2025-10-05 21:13:16.635183+00
\.


--
-- Name: notes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cgv
--

SELECT pg_catalog.setval('public.notes_id_seq', 5, true);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: cgv
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: notes notes_pkey; Type: CONSTRAINT; Schema: public; Owner: cgv
--

ALTER TABLE ONLY public.notes
    ADD CONSTRAINT notes_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\unrestrict IznG4Fky7IqJlFJLE0GaatopwchKeYw5zPTdwwa5IBkXbXoeLFqxrY2PuhZLQlN

