# Yellow Teaming — Security Engineering

Professional application for the Yellow Teaming (Security Engineering) specialisation, Fontys ICT semester 6 (Cyber Security Advanced, 2627nj).

## What this is

A small notes application, built and deployed with security-by-design in mind: Zero Trust Azure infrastructure (private App Service, no public network access, Front Door + WAF as the only public entry point), a self-built authentication layer (2FA + self-managed password storage, not delegated to a third-party identity provider), and a database with encryption demonstrated at multiple levels.

## Structure

- `terraform/` — infrastructure as code (Azure)
- `app/` — the notes application
- `scripts/` — one-off setup/bootstrap scripts, not part of the deployed application

## Status

Just started. Building incrementally, one BoK topic at a time.
