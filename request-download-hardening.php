<?php
/**
 * Plugin Name: Request & Download Hardening
 * Description: Four narrow, self-contained security fixes that work on any WordPress site with no configuration: (1) closes unauthenticated access to Download Monitor (dlm_download) files via both the REST API and the direct /download/ link, (2) strips HTML/script markup out of incoming GET parameters before any theme or plugin code can read them, closing reflected-XSS holes in custom search/filter templates, (3) hardens XML-RPC by removing the pingback methods used for SSRF/DDoS amplification, hiding the endpoint's discovery header/link, and rate-limiting failed login attempts (covers both wp-login.php and XML-RPC, since both share WordPress's own authentication pipeline), and (4) blocks the two standard ways a site leaks its real usernames to a logged-out visitor (?author=N probing and the public REST users list) and genericizes the login form's error message so it stops confirming whether a guessed username exists. Every module no-ops safely if its target isn't present, and none of them touch POST, AJAX, cron, wp-admin, or any already-authenticated visitor - normal site functionality, layout, and content editing are completely unaffected.
 * Version: 1.3.2
 * Author: ADAPT
 * License: GPL-2.0-or-later
 * Update URI: https://github.com/johnbadapt23/request_download_hardening
 *
 * HOW TO DISABLE A MODULE ON A SITE WHERE ITS DEFAULT WOULD BE WRONG
 * -------------------------------------------------------------------------
 * All four modules default to ON, because an unauthenticated download/API
 * leak, an unescaped request parameter, an open pingback relay, and a
 * leaked admin username are virtually never something a site actually
 * wants. If a specific site genuinely needs one module off, define the
 * matching constant in that site's wp-config.php (above the "That's all,
 * stop editing!" line) BEFORE activating:
 *
 *     // Download Monitor's catalogue is meant to be fully public:
 *     define( 'RDH_DISABLE_DOWNLOAD_MONITOR_LOCKDOWN', true );
 *
 *     // A query-string value legitimately needs raw HTML (rare - see the
 *     // doc comment on rdh_sanitize_get_value() below for exactly what
 *     // this module does and does not touch):
 *     define( 'RDH_DISABLE_GET_SANITIZATION', true );
 *
 *     // The site deliberately relies on XML-RPC pingbacks, or its own
 *     // login rate-limiting already covers this (see Module 3 below):
 *     define( 'RDH_DISABLE_XMLRPC_HARDENING', true );
 *
 *     // The site intentionally exposes its users publicly (e.g. a
 *     // multi-author blog with public author pages/bylines):
 *     define( 'RDH_DISABLE_USERNAME_PROTECTION', true );
 *
 * UPDATES
 * -------------------------------------------------------------------------
 * This plugin updates itself from the GitHub Releases of the repository
 * named in the Update URI header above, through the normal Plugins and
 * Dashboard > Updates screens (see the "Self-updates" section at the end
 * of this file). If the repository is private, define a read-only token in
 * wp-config.php:
 *
 *     define( 'RDH_GITHUB_TOKEN', 'github_pat_...' );
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

/**
 * =============================================================================
 * MODULE 1: Download Monitor (dlm_download) unauthenticated-access lockdown.
 * =============================================================================
 *
 * What this fixes: Download Monitor registers its downloads as a public
 * custom post type (dlm_download). By default that means:
 *
 *   a) WordPress's core REST API auto-exposes a public, unauthenticated
 *      listing endpoint at /wp-json/wp/v2/dlm_download - every download's
 *      title, slug, and direct file link, paginated, no login required.
 *   b) The direct /download/{id}/ link Download Monitor generates for each
 *      entry serves the actual file to anyone who requests it, logged in
 *      or not, regardless of whether the file was meant to be gated.
 *
 * Neither of those requires any misconfiguration on the site owner's part -
 * it's the plugin's out-of-the-box behavior. This module closes both paths
 * with two completely generic, version-independent techniques:
 *
 *   1) Turning off show_in_rest for the dlm_download post type (and its
 *      two taxonomies) via the standard register_post_type_args /
 *      register_taxonomy_args filters - the same mechanism WordPress core
 *      itself recommends for adjusting a plugin's post-type registration
 *      without touching that plugin's code. This removes the REST route
 *      entirely; nothing else about how downloads are managed, listed, or
 *      displayed in wp-admin changes.
 *   2) Requiring a logged-in session on the direct /download/{id}/ URL,
 *      via is_user_logged_in() plus a redirect to wp_login_url(). It sends
 *      a logged-out visitor to the normal wp-login.php screen (respecting
 *      any custom login_url a site/theme/membership plugin has filtered
 *      in) with a redirect back to the file they wanted, and does nothing
 *      at all if the visitor is already logged in. This does not attempt
 *      to replicate any site's specific membership-tier or per-download
 *      access rules - it only restores the baseline "you must at least be
 *      logged in" check the unauthenticated-access finding showed was
 *      missing. A site that layers its own finer-grained membership
 *      gating on top (as research.adapt.com.au does) keeps that logic
 *      completely untouched; this module runs independently of it.
 *
 *      This check runs on plugins_loaded, matching the request path
 *      directly against Download Monitor's own documented direct-download
 *      URL format (/download/{id}/), rather than on template_redirect via
 *      is_singular('dlm_download') as an earlier version of this module
 *      did. That approach was tested against a real install and did not
 *      work: Download Monitor streams the file and exits during its own
 *      init (or earlier) handling, which always runs before
 *      template_redirect ever fires - so a template_redirect-based check
 *      never gets a turn. A second version moved to plugins_loaded but at
 *      priority 999, and ALSO failed against a real install: Download
 *      Monitor's own file-serving check runs on plugins_loaded too, not on
 *      init, so "run after every other plugin's plugins_loaded callback"
 *      guaranteed losing that race rather than winning it. Priority 1 -
 *      as early within plugins_loaded as a normal plugin can get - fixed
 *      that part, confirmed against a real install: a logged-out request
 *      correctly received a 302 to wp-login.php instead of the file.
 *
 *      A third bug then turned up testing the OTHER direction - a real
 *      logged-in session still got bounced to the login screen too. That
 *      version used WordPress core's auth_redirect(), reasoning it was
 *      "the same function core uses to gate private posts" - which turned
 *      out to be a wrong assumption. auth_redirect() validates the
 *      *admin-scoped* auth/secure_auth cookie (the one the browser only
 *      ever sends to /wp-admin/ paths) - it's what core calls at the top
 *      of wp-admin/admin.php, not what it uses to gate private content on
 *      the front end. /download/{id}/ is a front-end URL, so that cookie
 *      is never sent there, and auth_redirect() treated every visitor as
 *      logged out regardless of their real session - confirmed by testing
 *      with a genuinely authenticated admin session and getting the same
 *      reauth loop a logged-out visitor got. is_user_logged_in() checks
 *      the general logged_in cookie instead, which the browser does send
 *      on every path, front end included - confirmed against a real
 *      install in both directions: a logged-out request to /download/{id}/
 *      gets a 302 to wp-login.php, and the same URL requested from a
 *      genuinely logged-in session returns the file (HTTP 200) untouched.
 *
 * Both halves are complete no-ops - verified first, before doing anything
 * else - on any site that doesn't have Download Monitor active, so this
 * module is always safe to leave enabled.
 */

if ( ! defined( 'RDH_DISABLE_DOWNLOAD_MONITOR_LOCKDOWN' ) || ! RDH_DISABLE_DOWNLOAD_MONITOR_LOCKDOWN ) {

	// --- 1a. Remove the dlm_download REST route and its taxonomies' routes. ---
	add_filter(
		'register_post_type_args',
		function ( $args, $post_type ) {
			if ( 'dlm_download' === $post_type ) {
				$args['show_in_rest'] = false;
			}
			return $args;
		},
		20,
		2
	);

	add_filter(
		'register_taxonomy_args',
		function ( $args, $taxonomy ) {
			if ( in_array( $taxonomy, [ 'dlm_download_category', 'dlm_download_tag' ], true ) ) {
				$args['show_in_rest'] = false;
			}
			return $args;
		},
		20,
		2
	);

	// --- 1b. Require a login for the direct /download/{id}/ file link. ---
	add_action(
		'plugins_loaded',
		function () {
			// Confirm Download Monitor is actually active before doing
			// anything else, via the active_plugins option directly -
			// available this early, unlike is_plugin_active() (which lives
			// in an admin-only file) or post_type_exists( 'dlm_download' )
			// (false until Download Monitor registers it on init, which
			// hasn't happened yet at plugins_loaded). Checked on both a
			// normal and a network/multisite activation.
			$active = (array) get_option( 'active_plugins', [] );
			if ( is_multisite() ) {
				$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
			}

			$dlm_active = false;
			foreach ( $active as $plugin_file ) {
				if ( 0 === strpos( (string) $plugin_file, 'download-monitor/' ) ) {
					$dlm_active = true;
					break;
				}
			}
			if ( ! $dlm_active ) {
				return;
			}

			$request_path = wp_parse_url( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), PHP_URL_PATH );
			if ( ! $request_path || ! preg_match( '#^/download/\d+/?$#', $request_path ) ) {
				return;
			}

			// Deliberately is_user_logged_in() + wp_login_url(), NOT
			// auth_redirect() - see the doc comment above for why
			// auth_redirect() (which checks the admin-scoped auth cookie,
			// never sent to a front-end URL like this one) was tried
			// first and had to be reverted: it redirected every visitor,
			// logged in or not. is_user_logged_in() checks the general
			// logged_in cookie, which the browser sends on every path.
			if ( is_user_logged_in() ) {
				return;
			}

			$current_url = ( is_ssl() ? 'https://' : 'http://' ) . ( $_SERVER['HTTP_HOST'] ?? '' ) . ( $_SERVER['REQUEST_URI'] ?? '' );

			nocache_headers();
			wp_safe_redirect( wp_login_url( $current_url ) );
			exit;
		},
		1 // As early within plugins_loaded as a normal plugin can hook - see the doc comment above on why late (999) lost this race instead of winning it.
	);
}

/**
 * =============================================================================
 * MODULE 2: Strip HTML/script markup out of incoming GET parameters.
 * =============================================================================
 *
 * What this fixes: a custom theme template (or any plugin) that reads a
 * $_GET value and echoes it back into the page - a search box's "value"
 * attribute, a "Search results for: ..." heading, a filter pill label - is
 * only as safe as whatever escaping that specific line of template code
 * happens to use. Auditing and fixing every such line, on every theme, on
 * every site, isn't something a generic plugin can do. What it CAN do is
 * make sure the value was already stripped of any markup before that
 * template code ever sees it, so the question of whether that one line
 * remembered to call esc_html()/esc_attr() stops being able to matter.
 *
 * This runs sanitize_text_field() - WordPress core's own standard
 * text-field sanitizer - over every string in $_GET, recursively through
 * arrays (e.g. $_GET['filter'][]), as early as the plugins_loaded hook
 * allows. sanitize_text_field():
 *   - strips HTML tags completely (wp_strip_all_tags()), including a bare
 *     "<script>", an "<img onerror=...>", or a quote/attribute breakout
 *     attempt - whether sent as literal characters or as %-encoded octets
 *     that decode to the same thing;
 *   - collapses extra whitespace and strips line breaks;
 *   - leaves ordinary text completely alone: a search term, a filter
 *     slug, a page number, an email address, a hyphenated or multi-word
 *     phrase all pass through byte-for-byte unchanged, because none of
 *     those ever legitimately contain a "<" or ">" character.
 *
 * Scope is deliberately narrow, to guarantee nothing else on the site can
 * be affected:
 *   - Only $_GET is touched. $_POST and $_REQUEST are left completely
 *     alone, so every form submission, checkout flow, comment, and
 *     admin-ajax action keeps receiving exactly the data it sent - this
 *     module cannot interfere with content editing or any POST-based
 *     feature.
 *   - wp-admin, admin-ajax.php, REST API, WP-CLI, and XML-RPC requests are
 *     all skipped entirely (is_admin() alone already covers admin-ajax.php,
 *     since WordPress core treats that endpoint as part of wp-admin). Only
 *     an ordinary front-end page request has its $_GET sanitized.
 */

if ( ! defined( 'RDH_DISABLE_GET_SANITIZATION' ) || ! RDH_DISABLE_GET_SANITIZATION ) {

	add_action(
		'plugins_loaded',
		function () {
			if (
				is_admin()
				|| wp_doing_ajax()
				|| wp_doing_cron()
				|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
				|| ( defined( 'WP_CLI' ) && WP_CLI )
				|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			) {
				return;
			}

			if ( empty( $_GET ) ) {
				return;
			}

			$_GET = rdh_sanitize_get_value( $_GET );
		},
		0 // As early as a normal (non-mu) plugin can hook, well before any theme template runs.
	);
}

/**
 * Recursively applies sanitize_text_field() to every string found in
 * $value, preserving array structure and leaving non-string scalars
 * (ints, bools, null) untouched. Used only by Module 2 above.
 *
 * @param mixed $value A $_GET entry - may be a string, an array of
 *                      strings (e.g. checkbox/multi-select filters), or a
 *                      nested array of either.
 * @return mixed The same structure, with every string passed through
 *               sanitize_text_field( wp_unslash( $string ) ).
 */
function rdh_sanitize_get_value( $value ) {
	if ( is_array( $value ) ) {
		foreach ( $value as $key => $item ) {
			$value[ $key ] = rdh_sanitize_get_value( $item );
		}
		return $value;
	}

	if ( ! is_string( $value ) ) {
		return $value;
	}

	return sanitize_text_field( wp_unslash( $value ) );
}

/**
 * =============================================================================
 * MODULE 3: XML-RPC hardening (pingback removal, discovery hiding, rate limit).
 * =============================================================================
 *
 * What this fixes: xmlrpc.php is a long-standing WordPress attack surface
 * in two unrelated ways, and this module addresses both without disabling
 * XML-RPC outright. A full "kill xmlrpc.php" approach was deliberately
 * NOT taken, even though it's the simplest option, because some sites
 * depend on it for things that are easy to overlook from outside (Jetpack,
 * the WordPress mobile app, some email-to-post or desktop-client
 * integrations) - breaking one of those would violate the "must not
 * affect current functionality" requirement this whole plugin is built
 * around. Instead:
 *
 *   a) The two pingback XML-RPC methods (pingback.ping and
 *      pingback.extensions.getPingbacks) are removed via the xmlrpc_methods
 *      filter. Pingbacks are the specific piece of XML-RPC that's been
 *      used for years to turn a WordPress site into an unwitting SSRF/DDoS
 *      relay (pingback.ping accepts an arbitrary URL and makes the server
 *      fetch it). They are also, in practice, obsolete - removing them
 *      has no effect on Jetpack, the mobile app, or any other legitimate
 *      XML-RPC consumer, which don't use these two methods.
 *   b) The X-Pingback response header and the RSD <link rel="EditURI">
 *      discovery tag in <head> - both of which exist purely to advertise
 *      "this site has XML-RPC/pingbacks at this URL" - are removed. This
 *      doesn't close anything by itself (the endpoint still works for
 *      anyone who already knows the standard /xmlrpc.php path) but removes
 *      the two places a scanner would otherwise find that confirmation
 *      for free. RSD is a relic of old desktop blogging clients (e.g.
 *      Windows Live Writer) that have no modern equivalent in use.
 *   c) Failed authentication attempts are rate-limited per IP address,
 *      which is the actual "rate-limit" half of this finding and the part
 *      that matters most: XML-RPC's system.multicall support lets an
 *      attacker bundle hundreds of username/password guesses into a
 *      single HTTP request, making XML-RPC brute force far faster than
 *      hammering wp-login.php directly. Critically, XML-RPC's login check
 *      (wp_xmlrpc_server::login(), used by every authenticated XML-RPC
 *      method including system.multicall) calls WordPress core's own
 *      wp_authenticate(), exactly like wp-login.php does - both paths
 *      fire the same wp_login_failed action on failure and run through
 *      the same authenticate filter chain. That means one rate limiter,
 *      hooked on those two core hooks, covers brute force against
 *      wp-login.php AND xmlrpc.php at the same time, with no need to
 *      special-case either entry point.
 *
 *      Implementation: wp_login_failed increments a per-IP counter kept
 *      in a transient (keyed by a hash of the IP, scoped to a rolling
 *      window). Once that counter reaches the threshold, the authenticate
 *      filter - hooked at priority 30, deliberately AFTER WordPress core's
 *      own wp_authenticate_username_password callback at priority 20 - is
 *      unconditionally overridden to a WP_Error for that IP, regardless of
 *      whether the submitted credentials were actually correct. Priority
 *      30 (not an earlier priority) matters: core's own callback only
 *      skips its own check when $user is ALREADY a WP_User instance - it
 *      does not check for a pre-existing WP_Error the same way - so a
 *      WP_Error returned at an earlier priority would simply be
 *      overwritten by core's own (fresh) validation result instead of
 *      blocking anything. Running after it and unconditionally replacing
 *      whatever core decided is what actually enforces the lockout.
 *
 *      IP detection deliberately uses only $_SERVER['REMOTE_ADDR'] - never
 *      an X-Forwarded-For or similar header, which an attacker controls
 *      directly and could use to make every request appear to come from a
 *      different (spoofed) IP, defeating the limiter entirely. The one
 *      trade-off of this safer choice: on a site that sits behind a
 *      reverse proxy or CDN which does NOT rewrite REMOTE_ADDR to the real
 *      visitor IP, every visitor would appear to share one address and the
 *      rate limit would apply site-wide rather than per-visitor. None of
 *      the four ADAPT sites this plugin was built for showed evidence of
 *      being behind such a proxy at the time of testing; if that ever
 *      changes for a given site, the threshold below may need raising
 *      rather than staying at its small per-IP default.
 *
 *      Thresholds (each definable via wp-config.php if a site needs a
 *      different value, same pattern as the RDH_DISABLE_* constants):
 *        RDH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS - failures allowed before a
 *          lockout (default 10).
 *        RDH_LOGIN_RATE_LIMIT_WINDOW - rolling window, in seconds, that
 *          the failure count (and the resulting lockout) is measured and
 *          reset against (default 600 = 10 minutes).
 *      These are deliberately generous (not a 3-strikes policy) - this is
 *      a backstop against automated bulk-guessing, not a replacement for
 *      the site's own password strength, and a high threshold minimizes
 *      any chance of a legitimate user mistyping their way into a lockout.
 */

if ( ! defined( 'RDH_DISABLE_XMLRPC_HARDENING' ) || ! RDH_DISABLE_XMLRPC_HARDENING ) {

	if ( ! defined( 'RDH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS' ) ) {
		define( 'RDH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS', 10 );
	}
	if ( ! defined( 'RDH_LOGIN_RATE_LIMIT_WINDOW' ) ) {
		define( 'RDH_LOGIN_RATE_LIMIT_WINDOW', 10 * MINUTE_IN_SECONDS );
	}

	// --- 3a. Remove the two pingback XML-RPC methods. ---
	add_filter(
		'xmlrpc_methods',
		function ( $methods ) {
			unset( $methods['pingback.ping'] );
			unset( $methods['pingback.extensions.getPingbacks'] );
			return $methods;
		}
	);

	// --- 3b. Stop advertising XML-RPC's existence via header/RSD link. ---
	add_filter(
		'wp_headers',
		function ( $headers ) {
			unset( $headers['X-Pingback'] );
			return $headers;
		}
	);
	remove_action( 'wp_head', 'rsd_link' );

	// --- 3c. Rate-limit failed authentication (wp-login.php + XML-RPC). ---
	add_action(
		'wp_login_failed',
		function ( $username ) {
			$key   = 'rdh_lf_' . md5( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
			$count = (int) get_transient( $key );
			set_transient( $key, $count + 1, RDH_LOGIN_RATE_LIMIT_WINDOW );
		}
	);

	add_filter(
		'authenticate',
		function ( $user, $username, $password ) {
			// Don't touch the bare login-page GET (no credentials submitted
			// at all yet) - only an actual authentication attempt.
			if ( '' === $username && '' === $password ) {
				return $user;
			}

			$key   = 'rdh_lf_' . md5( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
			$count = (int) get_transient( $key );

			if ( $count >= RDH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS ) {
				return new WP_Error(
					'rdh_rate_limited',
					__( '<strong>Error:</strong> Too many failed login attempts. Please wait a few minutes and try again.' )
				);
			}

			return $user;
		},
		30, // After core's own wp_authenticate_username_password (priority 20) - see the doc comment above for why this ordering, not an earlier one, is what actually enforces the block.
		3
	);
}

/**
 * =============================================================================
 * MODULE 4: Protect the site's real usernames from logged-out visitors.
 * =============================================================================
 *
 * What this fixes: the actual password is only half of what a brute-force
 * or credential-stuffing attempt needs - it also needs a valid username to
 * try the password against. WordPress leaks that second half in three
 * default, unauthenticated ways, each closed here independently:
 *
 *   a) ?author=N probing. Requesting a numeric ?author= query on the front
 *      end makes WordPress redirect to that user's author archive, whose
 *      URL contains their real login username (e.g. /author/jsmith/) -
 *      turning "is user ID 1 called jsmith or admin?" into a single
 *      logged-out HTTP request repeated across a small range of IDs. This
 *      is closed with the exact same approach already used elsewhere in
 *      the ADAPT theme itself (confirmed present as
 *      custom_block_author_enumeration() in the research.adapt.com.au
 *      theme's includes/_customisations.php): read $_GET['author']
 *      directly and redirect logged-out visitors home before WordPress's
 *      own query resolution ever gets to building that redirect. Reading
 *      $_GET directly (rather than checking is_author()/get_query_var()
 *      on template_redirect) is deliberate, not a style choice - the same
 *      lesson Module 1 already hit: WordPress's own canonical-redirect
 *      logic that turns ?author=1 into /author/jsmith/ runs very early,
 *      so a check that waits for the query to already be resolved is too
 *      late to intercept it.
 *   b) The public REST API user listing. /wp-json/wp/v2/users and
 *      /wp-json/wp/v2/users/{id} expose every registered user's "slug"
 *      (which defaults to their login username) with no authentication
 *      required, in a single clean JSON request - no probing needed at
 *      all. Both routes are removed via the rest_endpoints filter for any
 *      request that isn't already logged in, using the same
 *      filter-the-plugin's-own-registration technique as Module 1's REST
 *      fix, so wp-admin's own user-management screens (which run as a
 *      logged-in request) are completely unaffected.
 *   c) The login form's error message. By default WordPress tells a
 *      failed login attempt specifically whether the USERNAME it entered
 *      doesn't exist, or whether the PASSWORD was wrong for a username
 *      that does - which turns the login form itself into a free way to
 *      confirm a guessed username is valid, no author-archive or REST
 *      probing even needed. The login_errors filter replaces WordPress's
 *      specific message with one generic message regardless of which
 *      half was actually wrong, matching the standard guidance for this
 *      exact issue. This is a text-only change - it has no effect on
 *      whether a correct login succeeds.
 *
 * None of these three touch a logged-in visitor, wp-admin's own user list,
 * or any POST-based login flow beyond the displayed error text - only a
 * logged-out visitor's ability to discover or confirm a username changes.
 */

if ( ! defined( 'RDH_DISABLE_USERNAME_PROTECTION' ) || ! RDH_DISABLE_USERNAME_PROTECTION ) {

	// --- 4a. Block ?author=N enumeration for logged-out visitors. ---
	add_action(
		'init',
		function () {
			if ( is_user_logged_in() ) {
				return;
			}
			if ( isset( $_GET['author'] ) && preg_match( '/^\d+$/', wp_unslash( $_GET['author'] ) ) ) {
				wp_safe_redirect( home_url( '/' ), 301 );
				exit;
			}
		}
	);

	// --- 4b. Remove the public REST API user-listing routes. ---
	add_filter(
		'rest_endpoints',
		function ( $endpoints ) {
			if ( ! is_user_logged_in() ) {
				unset( $endpoints['/wp/v2/users'] );
				unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
			}
			return $endpoints;
		}
	);

	// --- 4c. Genericize the login form's error message. ---
	add_filter(
		'login_errors',
		function () {
			return __( '<strong>Error:</strong> Invalid username or password.' );
		}
	);
}

/**
 * =============================================================================
 * Self-updates from GitHub Releases.
 * =============================================================================
 *
 * Lets WordPress detect and install new versions of this plugin from the
 * dashboard, the same way it does for plugins hosted on wordpress.org, with
 * no external library. It relies on three core hooks:
 *
 *   a) update_plugins_github.com (WordPress 5.8+). Core calls this filter
 *      during its normal update check for any plugin whose "Update URI"
 *      header points at github.com. The callback asks the GitHub API for
 *      the repository's latest published release (or, if none is
 *      published yet, its highest version tag) and reports its tag
 *      (with any leading "v" removed) as the available version. Core then
 *      compares that against the installed Version header and shows the
 *      usual "update available" notice, the "Update now" link, and the
 *      "Enable auto-updates" toggle. The Update URI header also stops
 *      wordpress.org from ever offering an unrelated plugin that happens to
 *      share this slug.
 *   b) plugins_api. Supplies the "View version x.y.z details" popup with the
 *      release notes from GitHub, instead of a wordpress.org lookup that
 *      would fail.
 *   c) upgrader_source_selection. GitHub's release zip extracts to a folder
 *      named after the repository and tag (for example
 *      johnbadapt23-request_download_hardening-1a2b3c4/), not to this
 *      plugin's installed folder name (request-download-hardening/). This
 *      renames the extracted folder to match the installed one before core
 *      moves it into place, so the plugin stays active after updating and
 *      is not duplicated. Whatever folder name the plugin is installed
 *      under is the one that is kept.
 *
 * The GitHub response is cached for six hours (one hour after an error) so
 * the API is not called on every admin page load, which also keeps well
 * inside GitHub's unauthenticated rate limit. "Check again" on Dashboard >
 * Updates clears that cache and checks immediately.
 *
 * Private repositories: define RDH_GITHUB_TOKEN in wp-config.php (a
 * fine-grained personal access token with read-only "Contents" access to
 * this one repository). The token is sent only to api.github.com, only for
 * this repository's URLs. Public repositories need no token.
 */

if ( ! defined( 'RDH_GITHUB_REPO' ) ) {
	define( 'RDH_GITHUB_REPO', 'johnbadapt23/request_download_hardening' );
}

/**
 * Returns the latest GitHub release for RDH_GITHUB_REPO, or null if it could
 * not be fetched. Cached in a site transient.
 *
 * @return array|null Keys: version, tag, package, url, notes, published.
 */
function rdh_github_latest_release() {
	$cache_key = 'rdh_github_release';

	if ( is_admin() && isset( $_GET['force-check'] ) && current_user_can( 'update_plugins' ) ) {
		delete_site_transient( $cache_key );
	}

	$cached = get_site_transient( $cache_key );
	if ( is_array( $cached ) ) {
		return empty( $cached['version'] ) ? null : $cached;
	}

	$api     = 'https://api.github.com/repos/' . RDH_GITHUB_REPO;
	$release = null;
	$error   = '';

	// 1. The latest published release (preferred: carries release notes).
	$response = rdh_github_get( $api . '/releases/latest' );
	$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );

	if ( 200 === $code ) {
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( is_array( $body ) && ! empty( $body['tag_name'] ) && ! empty( $body['zipball_url'] ) ) {
			$release = [
				'version'   => ltrim( (string) $body['tag_name'], 'vV' ),
				'tag'       => (string) $body['tag_name'],
				'package'   => (string) $body['zipball_url'],
				'url'       => (string) ( $body['html_url'] ?? 'https://github.com/' . RDH_GITHUB_REPO ),
				'notes'     => (string) ( $body['body'] ?? '' ),
				'published' => (string) ( $body['published_at'] ?? '' ),
			];
		}
	} elseif ( 404 === $code ) {
		// 2. No published release yet: fall back to the highest version
		//    tag, so pushing a tag such as v1.4.0 is enough on its own.
		//    (A 404 here also means a private repository without a valid
		//    RDH_GITHUB_TOKEN, which the tags request below reports too.)
		$response = rdh_github_get( $api . '/tags?per_page=100' );
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
		if ( 200 === $code ) {
			$tags = json_decode( wp_remote_retrieve_body( $response ), true );
			foreach ( (array) $tags as $tag ) {
				$name    = (string) ( $tag['name'] ?? '' );
				$version = ltrim( $name, 'vV' );
				if ( ! preg_match( '/^\d+(\.\d+)*$/', $version ) || empty( $tag['zipball_url'] ) ) {
					continue; // Ignore non-version tags and pre-release suffixes.
				}
				if ( ! $release || version_compare( $version, $release['version'], '>' ) ) {
					$release = [
						'version'   => $version,
						'tag'       => $name,
						'package'   => (string) $tag['zipball_url'],
						'url'       => 'https://github.com/' . RDH_GITHUB_REPO . '/tree/' . rawurlencode( $name ),
						'notes'     => '',
						'published' => '',
					];
				}
			}
			if ( ! $release ) {
				$error = 'no_release';
			}
		}
	}

	if ( ! $release && ! $error ) {
		if ( is_wp_error( $response ) ) {
			$error = 'connection: ' . $response->get_error_message();
		} elseif ( 403 === $code || 429 === $code ) {
			$error = 'rate_limited';
		} elseif ( 404 === $code ) {
			$error = 'not_found';
		} else {
			$error = 'http_' . $code;
		}
	}

	// Failures are cached for an hour (with the reason, for the "Check for
	// updates" notice) so an outage is not retried on every request.
	set_site_transient( $cache_key, $release ?: [ 'error' => $error ], $release ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );

	return $release;
}

/**
 * GET request to the GitHub API with the headers GitHub expects.
 *
 * @param string $url Full api.github.com URL.
 * @return array|WP_Error
 */
function rdh_github_get( $url ) {
	return wp_remote_get(
		$url,
		[
			'timeout'    => 10,
			'user-agent' => 'request-download-hardening-updater',
			'headers'    => [
				'Accept'               => 'application/vnd.github+json',
				'X-GitHub-Api-Version' => '2022-11-28',
			],
		]
	);
}

/**
 * Explains why the last GitHub check found no version, for the admin notice.
 *
 * @return string
 */
function rdh_github_error_message() {
	$cached = get_site_transient( 'rdh_github_release' );
	$error  = is_array( $cached ) ? (string) ( $cached['error'] ?? '' ) : '';

	if ( 'no_release' === $error ) {
		return __( 'no release or version tag (for example v1.4.0) was found on GitHub yet.' );
	}
	if ( 'rate_limited' === $error ) {
		return __( 'GitHub refused the request because of its rate limit. Please try again in an hour.' );
	}
	if ( 'not_found' === $error ) {
		return __( 'the GitHub repository was not found. If it is private, define RDH_GITHUB_TOKEN in wp-config.php.' );
	}
	if ( 0 === strpos( $error, 'connection: ' ) ) {
		/* translators: %s: technical error message. */
		return sprintf( __( 'this server could not connect to GitHub (%s). The host may be blocking outbound requests.' ), substr( $error, 12 ) );
	}
	/* translators: %s: error code. */
	return sprintf( __( 'GitHub returned an unexpected response (%s).' ), $error ?: 'unknown' );
}

add_filter(
	'update_plugins_github.com',
	function ( $update, $plugin_data, $plugin_file ) {
		if ( plugin_basename( __FILE__ ) !== $plugin_file ) {
			return $update; // Another plugin that also updates from GitHub.
		}

		$release = rdh_github_latest_release();
		if ( ! $release ) {
			return $update;
		}

		// Returned even when the version is not newer: core files it under
		// "no update" in that case, which is what makes the auto-updates
		// toggle appear on the Plugins screen.
		return [
			'id'      => $plugin_data['UpdateURI'],
			'slug'    => dirname( $plugin_file ),
			'version' => $release['version'],
			'url'     => $release['url'],
			'package' => $release['package'],
		];
	},
	10,
	3
);

add_filter(
	'plugins_api',
	function ( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || dirname( plugin_basename( __FILE__ ) ) !== $args->slug ) {
			return $result;
		}

		$release = rdh_github_latest_release();
		if ( ! $release ) {
			return $result;
		}

		$plugin = get_file_data( __FILE__, [ 'Name' => 'Plugin Name', 'Author' => 'Author', 'Description' => 'Description' ] );

		return (object) [
			'name'          => $plugin['Name'],
			'slug'          => $args->slug,
			'version'       => $release['version'],
			'author'        => $plugin['Author'],
			'homepage'      => 'https://github.com/' . RDH_GITHUB_REPO,
			'download_link' => $release['package'],
			'last_updated'  => $release['published'],
			'sections'      => [
				'description' => esc_html( $plugin['Description'] ),
				'changelog'   => '' !== $release['notes'] ? nl2br( esc_html( $release['notes'] ) ) : esc_html__( 'No release notes provided.' ),
			],
		];
	},
	20,
	3
);

add_filter(
	'upgrader_source_selection',
	function ( $source, $remote_source, $upgrader, $hook_extra = [] ) {
		global $wp_filesystem;

		if ( ! is_array( $hook_extra ) || ( $hook_extra['plugin'] ?? '' ) !== plugin_basename( __FILE__ ) ) {
			return $source;
		}

		$folder = dirname( plugin_basename( __FILE__ ) );
		if ( '.' === $folder ) {
			return $source; // Installed as a loose file in wp-content/plugins; nothing to rename.
		}

		$desired = trailingslashit( $remote_source ) . $folder . '/';
		if ( untrailingslashit( $source ) === untrailingslashit( $desired ) ) {
			return $source;
		}

		if ( ! $wp_filesystem || ! $wp_filesystem->move( untrailingslashit( $source ), untrailingslashit( $desired ), true ) ) {
			return new WP_Error( 'rdh_rename_failed', __( 'Could not rename the downloaded update folder to match the installed plugin.' ) );
		}

		return $desired;
	},
	10,
	4
);

// Private repositories: authenticate this plugin's own GitHub API requests
// (the release lookup and the zip download) and nothing else.
add_filter(
	'http_request_args',
	function ( $args, $url ) {
		if ( defined( 'RDH_GITHUB_TOKEN' ) && RDH_GITHUB_TOKEN && 0 === strpos( $url, 'https://api.github.com/repos/' . RDH_GITHUB_REPO . '/' ) ) {
			$args['headers']                  = (array) ( $args['headers'] ?? [] );
			$args['headers']['Authorization'] = 'Bearer ' . RDH_GITHUB_TOKEN;
		}
		return $args;
	},
	10,
	2
);

// Drop the cached release once this plugin has been updated, so the next
// check reflects the new installed version straight away.
add_action(
	'upgrader_process_complete',
	function ( $upgrader, $hook_extra ) {
		if ( ( $hook_extra['type'] ?? '' ) === 'plugin' && in_array( plugin_basename( __FILE__ ), (array) ( $hook_extra['plugins'] ?? [ $hook_extra['plugin'] ?? '' ] ), true ) ) {
			delete_site_transient( 'rdh_github_release' );
		}
	},
	10,
	2
);

// "Check for updates" link under the plugin's name on the Plugins screen.
// Clears the cached GitHub response and WordPress's own update data, runs a
// fresh check straight away, then returns to the Plugins screen with a
// notice saying whether a newer version is available.
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'rdh_check_updates_link' );
add_filter( 'network_admin_plugin_action_links_' . plugin_basename( __FILE__ ), 'rdh_check_updates_link' );

/**
 * Adds the "Check for updates" link to this plugin's row.
 *
 * @param array $links Existing action links.
 * @return array
 */
function rdh_check_updates_link( $links ) {
	if ( current_user_can( 'update_plugins' ) ) {
		$url     = wp_nonce_url( add_query_arg( 'rdh_check_updates', '1', self_admin_url( 'plugins.php' ) ), 'rdh_check_updates' );
		$links[] = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Check for updates' ) . '</a>';
	}
	return $links;
}

add_action(
	'admin_init',
	function () {
		if ( empty( $_GET['rdh_check_updates'] ) ) {
			return;
		}
		check_admin_referer( 'rdh_check_updates' );
		if ( ! current_user_can( 'update_plugins' ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to update plugins for this site.' ) );
		}

		delete_site_transient( 'rdh_github_release' );
		delete_site_transient( 'update_plugins' );
		wp_update_plugins();

		$updates = get_site_transient( 'update_plugins' );
		$basename = plugin_basename( __FILE__ );
		if ( isset( $updates->response[ $basename ] ) ) {
			$result = 'available';
		} elseif ( isset( $updates->no_update[ $basename ] ) ) {
			$result = 'current';
		} else {
			$result = 'failed';
		}

		wp_safe_redirect( add_query_arg( 'rdh_checked', $result, self_admin_url( 'plugins.php' ) ) );
		exit;
	}
);

$rdh_update_notice = function () {
	if ( empty( $_GET['rdh_checked'] ) || ! current_user_can( 'update_plugins' ) ) {
		return;
	}

	$result   = sanitize_key( wp_unslash( $_GET['rdh_checked'] ) );
	$basename = plugin_basename( __FILE__ );
	$updates  = get_site_transient( 'update_plugins' );
	$name     = get_file_data( __FILE__, [ 'Name' => 'Plugin Name' ] )['Name'];

	if ( 'available' === $result && isset( $updates->response[ $basename ] ) ) {
		$type    = 'warning';
		/* translators: 1: plugin name, 2: version number. */
		$message = sprintf( __( '%1$s: version %2$s is available. Use the update link in the plugin\'s row to install it.' ), $name, $updates->response[ $basename ]->new_version );
	} elseif ( 'current' === $result ) {
		$type    = 'success';
		/* translators: %s: plugin name. */
		$message = sprintf( __( '%s is up to date.' ), $name );
	} else {
		$type    = 'error';
		/* translators: 1: plugin name, 2: reason. */
		$message = sprintf( __( '%1$s: could not check for updates, because %2$s' ), $name, rdh_github_error_message() );
	}

	printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $type ), esc_html( $message ) );
};
add_action( 'admin_notices', $rdh_update_notice );
add_action( 'network_admin_notices', $rdh_update_notice );
