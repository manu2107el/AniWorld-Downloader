import logging
from flask import Blueprint, jsonify, request, current_app
from ..utils import require_api_auth # Removed _get_user_from_session_token as it's not used

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route("/search", methods=["POST"])
@require_api_auth
def api_search():
    """Search for anime endpoint."""
    try:
        data = request.get_json()
        if not data or "query" not in data:
            return jsonify(
                {"success": False, "error": "Query parameter is required"}
            ), 400

        query = data["query"].strip()
        if not query:
            return jsonify(
                {"success": False, "error": "Query cannot be empty"}
            ), 400

        # Get site parameter (default to both)
        site = data.get("site", "both")

        # Import necessary modules from parent package
        from ...search import fetch_anime_list, search_anime, fetch_popular_and_new_anime
        from ... import config
        from urllib.parse import quote

        # Create wrapper function for search with dual-site support
        def search_anime_wrapper(keyword, site="both"):
            """Wrapper function for anime search with multi-site support"""
            if site == "both":
                # Search both sites using existing fetch_anime_list function
                aniworld_url = f"{config.ANIWORLD_TO}/ajax/seriesSearch?keyword={quote(keyword)}"
                sto_url = (
                    f"{config.S_TO}/ajax/seriesSearch?keyword={quote(keyword)}"
                )

                # Fetch from both sites
                aniworld_results = []
                sto_results = []

                try:
                    aniworld_results = fetch_anime_list(aniworld_url)
                except Exception as e:
                    logging.warning(f"Failed to fetch from aniworld: {e}")

                try:
                    sto_results = fetch_anime_list(sto_url)
                except Exception as e:
                    logging.warning(f"Failed to fetch from s.to: {e}")

                # Combine and deduplicate results
                all_results = []
                seen_slugs = set()

                # Add aniworld results first
                for anime in aniworld_results:
                    slug = anime.get("link", "")
                    if slug and slug not in seen_slugs:
                        anime["site"] = "aniworld.to"
                        anime["base_url"] = config.ANIWORLD_TO
                        anime["stream_path"] = "anime/stream"
                        all_results.append(anime)
                        seen_slugs.add(slug)

                # Add s.to results, but skip duplicates
                for anime in sto_results:
                    slug = anime.get("link", "")
                    if slug and slug not in seen_slugs:
                        anime["site"] = "s.to"
                        anime["base_url"] = config.S_TO
                        anime["stream_path"] = "serie/stream"
                        all_results.append(anime)
                        seen_slugs.add(slug)

                return all_results

            elif site == "s.to":
                # Single site search - s.to
                search_url = (
                    f"{config.S_TO}/ajax/seriesSearch?keyword={quote(keyword)}"
                )
                try:
                    results = fetch_anime_list(search_url)
                    for anime in results:
                        anime["site"] = "s.to"
                        anime["base_url"] = config.S_TO
                        anime["stream_path"] = "serie/stream"
                    return results
                except Exception as e:
                    logging.error(f"s.to search failed: {e}")
                    return []

            else:
                # Single site search - aniworld.to (default)
                try:
                    results = search_anime(keyword=keyword, only_return=True)
                    for anime in results:
                        anime["site"] = "aniworld.to"
                        anime["base_url"] = config.ANIWORLD_TO
                        anime["stream_path"] = "anime/stream"
                    return results
                except Exception as e:
                    logging.error(f"aniworld.to search failed: {e}")
                    return []

        # Use wrapper function
        results = search_anime_wrapper(query, site)

        # Process results - simplified without episode fetching
        processed_results = []
        for anime in results[:50]:  # Limit to 50 results
            # Get the link and construct full URL if needed
            link = anime.get("link", "")
            anime_site = anime.get("site", "aniworld")
            anime_base_url = anime.get("base_url", config.ANIWORLD_TO)
            anime_stream_path = anime.get("stream_path", "anime/stream")

            if link and not link.startswith("http"):
                # If it's just a slug, construct the full URL using the anime's specific site info
                full_url = f"{anime_base_url}/{anime_stream_path}/{link}"
            else:
                full_url = link

            # Use the same field names as CLI search
            name = anime.get("name", "Unknown Name")
            year = anime.get("productionYear", "Unknown Year")

            # Create title like CLI does, but avoid double parentheses
            if year and year != "Unknown Year" and str(year) not in name:
                title = f"{name} {year}"
            else:
                title = name

            processed_anime = {
                "title": title,
                "url": full_url,
                "description": anime.get("description", ""),
                "slug": link,
                "name": name,
                "year": year,
                "site": anime_site,
                "cover": anime.get("cover", ""),
            }

            processed_results.append(processed_anime)

        return jsonify(
            {
                "success": True,
                "results": processed_results,
                "count": len(processed_results),
            }
        )

    except Exception as err:
        logging.error(f"Search error: {err}")
        return jsonify(
            {"success": False, "error": f"Search failed: {str(err)}"}
        ), 500

@api_bp.route("/download", methods=["POST"])
@require_api_auth
def api_download():
    """Start download endpoint."""
    try:
        data = request.get_json()

        # Check for both single episode (legacy) and multiple episodes (new)
        episode_urls = data.get("episode_urls", [])
        single_episode_url = data.get("episode_url")

        if single_episode_url:
            episode_urls = [single_episode_url]

        if not episode_urls:
            return jsonify(
                {"success": False, "error": "Episode URL(s) required"}
            ), 400

        language = data.get("language", "German Sub")
        provider = data.get("provider", "VOE")

        # Get current user for queue tracking
        current_user = None # This was previously _get_user_from_session_token()
        auth_enabled = current_app.config.get("AUTH_ENABLED", False)
        db = current_app.config.get("DB")
        if auth_enabled and db:
            session_token = request.cookies.get("session_token")
            current_user = db.get_user_by_session(session_token)


        # Determine anime title
        anime_title = data.get("anime_title", "Unknown Anime")

        # Calculate total episodes by checking episode URLs
        from ...entry import _group_episodes_by_series

        try:
            anime_list = _group_episodes_by_series(episode_urls)
            total_episodes = sum(
                len(anime.episode_list) for anime in anime_list
            )
        except Exception as e:
            logging.error(f"Failed to process episode URLs: {e}")
            return jsonify(
                {
                    "success": False,
                    "error": "No valid anime objects could be created from provided URLs",
                }
            ), 400

        if total_episodes == 0:
            return jsonify(
                {
                    "success": False,
                    "error": "No valid anime objects could be created from provided URLs",
                }
            ), 400

        download_manager = current_app.config.get("DOWNLOAD_MANAGER")
        if not download_manager:
            return jsonify(
                {"success": False, "error": "Download manager not available"}
            ), 500

        # Add to download queue
        queue_id = download_manager.add_download(
            anime_title=anime_title,
            episode_urls=episode_urls,
            language=language,
            provider=provider,
            total_episodes=total_episodes,
            created_by=current_user["id"] if current_user else None,
        )

        if not queue_id:
            return jsonify(
                {"success": False, "error": "Failed to add download to queue"}
            ), 500

        return jsonify(
            {
                "success": True,
                "message": f"Download added to queue: {total_episodes} episode(s)",
                "episode_count": total_episodes,
                "language": language,
                "provider": provider,
                "queue_id": queue_id,
            }
        )

    except Exception as err:
        logging.error(f"Download error: {err}")
        return jsonify(
            {"success": False, "error": f"Failed to start download: {str(err)}"}
        ), 500

@api_bp.route("/download-path")
@require_api_auth
def api_download_path():
    """Get download path endpoint."""
    try:
        # Use arguments.output_dir if available, otherwise fall back to default
        config_obj = current_app.config.get("CONFIG")
        arguments = current_app.config.get("ARGUMENTS")

        download_path = str(config_obj.DEFAULT_DOWNLOAD_PATH)
        if (
            arguments
            and hasattr(arguments, "output_dir")
            and arguments.output_dir is not None
        ):
            download_path = str(arguments.output_dir)

        return jsonify({"path": download_path})
    except Exception as err:
        logging.error(f"Failed to get download path: {err}")
        return jsonify({"path": str(current_app.config["CONFIG"].DEFAULT_DOWNLOAD_PATH)}), 500

@api_bp.route("/episodes", methods=["POST"])
@require_api_auth
def api_episodes():
    """Get episodes for a series endpoint."""
    try:
        data = request.get_json()
        if not data or "series_url" not in data:
            return jsonify(
                {"success": False, "error": "Series URL is required"}
            ), 400

        series_url = data["series_url"]

        # Create wrapper function to handle all logic
        def get_episodes_for_series(series_url):
            """Wrapper function using existing functions to get episodes and movies"""
            from ...common import (
                get_season_episode_count,
                get_movie_episode_count,
            )
            from ...entry import _detect_site_from_url
            from ... import config

            # Extract slug and site using existing functions
            _site = _detect_site_from_url(series_url)

            if "/anime/stream/" in series_url:
                slug = series_url.split("/anime/stream/")[-1].rstrip("/")
                stream_path = "anime/stream"
                base_url = config.ANIWORLD_TO
            elif "/serie/stream/" in series_url:
                slug = series_url.split("/serie/stream/")[-1].rstrip("/")
                stream_path = "serie/stream"
                base_url = config.S_TO
            else:
                raise ValueError("Invalid series URL format")

            # Use existing function to get season/episode counts
            season_counts = get_season_episode_count(slug, base_url)

            # Build episodes structure
            episodes_by_season = {}
            for season_num, episode_count in season_counts.items():
                if episode_count > 0:
                    episodes_by_season[season_num] = []
                    for ep_num in range(1, episode_count + 1):
                        episodes_by_season[season_num].append(
                            {
                                "season": season_num,
                                "episode": ep_num,
                                "title": f"Episode {ep_num}",
                                "url": f"{base_url}/{stream_path}/{slug}/staffel-{season_num}/episode-{ep_num}",
                            }
                        )

            # Get movies if this is from aniworld.to (movies only available there)
            movies = []
            if base_url == config.ANIWORLD_TO:
                try:
                    movie_count = get_movie_episode_count(slug)
                    for movie_num in range(1, movie_count + 1):
                        movies.append(
                            {
                                "movie": movie_num,
                                "title": f"Movie {movie_num}",
                                "url": f"{base_url}/{stream_path}/{slug}/filme/film-{movie_num}",
                            }
                        )
                except Exception as e:
                    logging.warning(
                        f"Failed to get movie count for {slug}: {e}"
                    )

            # Fallback if no seasons found
            if not episodes_by_season and not movies:
                # If no seasons and no movies, return an empty structure
                return {}, [], slug


            return episodes_by_season, movies, slug

        # Use the wrapper function
        try:
            episodes_by_season, movies, slug = get_episodes_for_series(
                series_url
            )
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception as e:
            logging.error(f"Failed to get episodes: {e}")
            return jsonify(
                {"success": False, "error": "Failed to fetch episodes"}
            ), 500

        return jsonify(
            {
                "success": True,
                "episodes": episodes_by_season,
                "movies": movies,
                "slug": slug,
            }
        )

    except Exception as err:
        logging.error(f"Episodes fetch error: {err}")
        return jsonify(
            {"success": False, "error": f"Failed to fetch episodes: {str(err)}"}
        ), 500

@api_bp.route("/queue-status")
@require_api_auth
def api_queue_status():
    """Get download queue status endpoint."""
    try:
        download_manager = current_app.config.get("DOWNLOAD_MANAGER")
        if not download_manager:
            return jsonify(
                {"success": False, "error": "Download manager not available"}
            ), 500

        queue_status = download_manager.get_queue_status()

        return jsonify({"success": True, "queue": queue_status})
    except Exception as e:
        logging.error(f"Failed to get queue status: {e}")
        return jsonify(
            {"success": False, "error": "Failed to get queue status"}
        ), 500

@api_bp.route("/popular-new")
@require_api_auth
def api_popular_new():
    """Get popular and new anime endpoint."""
    try:
        from ...search import fetch_popular_and_new_anime

        anime_data = fetch_popular_and_new_anime()
        return jsonify(
            {
                "success": True,
                "popular": anime_data.get("popular", []),
                "new": anime_data.get("new", []),
            }
        )
    except Exception as e:
        logging.error(f"Failed to fetch popular/new anime: {e}")
        return jsonify(
            {"success": False, "error": f"Failed to fetch popular/new anime: {str(e)}",}
        ), 500