/*
 * Copyright 2024 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <avs_commons_init.h>

#include <ctype.h>
#include <string.h>

#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_stream_netbuf.h>
#include <avsystem/commons/avs_unit_mocksock.h>
#include <avsystem/commons/avs_unit_test.h>

#include "test_http.h"

#include "src/http/avs_body_receivers.h"

#define MODULE_NAME http_test
#include <avs_x_log_config.h>

AVS_UNIT_GLOBAL_INIT(verbose) {
    if (!verbose) {
        avs_log_set_default_level(AVS_LOG_QUIET);
    }
}

expected_socket_t *avs_http_test_SOCKETS_TO_CREATE = NULL;

static avs_error_t test_socket_create(avs_net_socket_t **socket,
                                      avs_net_socket_type_t type) {
    expected_socket_t *removed_entry;
    removed_entry = AVS_LIST_DETACH(&avs_http_test_SOCKETS_TO_CREATE);
    AVS_UNIT_ASSERT_NOT_NULL(removed_entry);
    AVS_UNIT_ASSERT_EQUAL(type, removed_entry->type);
    *socket = removed_entry->socket;
    AVS_LIST_DELETE(&removed_entry);
    return (*socket) ? AVS_OK : avs_errno(AVS_ENOMEM);
}

avs_error_t avs_net_tcp_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...) {
    return test_socket_create(socket, AVS_NET_TCP_SOCKET);
}

avs_error_t avs_net_ssl_socket_create_TEST_WRAPPER(avs_net_socket_t **socket,
                                                   ...) {
    return test_socket_create(socket, AVS_NET_SSL_SOCKET);
}

void avs_http_test_expect_create_socket(avs_net_socket_t *socket,
                                        avs_net_socket_type_t type) {
    expected_socket_t *new_socket = AVS_LIST_NEW_ELEMENT(expected_socket_t);
    AVS_UNIT_ASSERT_NOT_NULL(new_socket);
    new_socket->socket = socket;
    new_socket->type = type;
    AVS_LIST_APPEND(&avs_http_test_SOCKETS_TO_CREATE, new_socket);
}

AVS_UNIT_TEST(http, full_request) {
    const char *tmp_data = NULL;
    char buffer[64];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.zombo.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.zombo.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "Welcome\n"));
    avs_unit_mocksock_assert_io_clean(socket);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: www.zombo.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 22\r\n"
               "\r\n"
               "Welcome\n"
               "to Zombo.com!\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "to Zombo.com!\n"));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    tmp_data = "You can do anything\n"
               "at Zombo.com!\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                stream, &bytes_read, &message_finished, buffer_ptr,
                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(tmp_data));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, tmp_data);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, reconnect_fail) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.avsystem.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.avsystem.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.avsystem.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);

    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "www.avsystem.com", "80");
    avs_unit_mocksock_fail_command(socket, avs_errno(AVS_ECONNREFUSED));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_ECONNREFUSED);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, advanced_request) {
    const char *tmp_data;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("HtTp://pentagon.osd.mil/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "pentagon.osd.mil", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 "root", "12345"));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    AVS_UNIT_ASSERT_SUCCESS(avs_http_add_header(stream, "I-Am", "h4x0r"));
    tmp_data = "GET / HTTP/1.1\r\n" /* first request */
               "Host: pentagon.osd.mil\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "I-Am: h4x0r\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* first response */
               "WWW-Authenticate: Basic realm=\"JIGOKU DESU\"\r\n"
               "Set-Cookie: nyan=cat\r\n"
               "Set-Cookie2: nyan=azu\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = "GET / HTTP/1.1\r\n" /* second request */
               "Host: pentagon.osd.mil\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Authorization: Basic cm9vdDoxMjM0NQ==\r\n"
               "Cookie: $Version=\"1\"; nyan=azu\r\n"
               "I-Am: h4x0r\r\n"
               "\r\n"; /* no third request - fail after two 401's */
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* second response */
               "WWW-Authenticate: Basic realm=\"JIGOKU DESU\"\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_HTTP_ERROR_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, 401);
    AVS_UNIT_ASSERT_EQUAL(avs_http_status_code(stream), 401);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, invalid_cookies) {
    const char *tmp_data;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://avsystem.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "avsystem.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 "wacek", "ala123"));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n" /* first request */
               "Host: avsystem.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n" /* first response */
               "Set-Cookie: invalid\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EPROTO);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, multiple_cookies) {
    const char *tmp_data;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://unicodesnowmanforyou.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "unicodesnowmanforyou.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 "omae_wa", "mou_shindeiru"));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n" /* first request */
               "Host: unicodesnowmanforyou.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* first response */
               "WWW-Authenticate: Basic realm=\"NANI?!\"\r\n"
               "Set-Cookie: sleeper=wake_up\r\n"
               "Set-Cookie: wake_up=sleeper\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = "GET / HTTP/1.1\r\n" /* second request */
               "Host: unicodesnowmanforyou.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Authorization: Basic b21hZV93YTptb3Vfc2hpbmRlaXJ1\r\n"
               "Cookie: sleeper=wake_up; wake_up=sleeper\r\n"
               "\r\n"; /* no third request - fail after two 401's */
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 401 Unauthorized\r\n" /* second response */
               "WWW-Authenticate: Basic realm=\"NANI?!\"\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_HTTP_ERROR_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, 401);
    AVS_UNIT_ASSERT_EQUAL(avs_http_status_code(stream), 401);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

const char *const MONTY_PYTHON_RAW =
        "A customer enters a pet shop.\n"
        "Customer: 'Ello, I wish to register a complaint.\n"
        "(The owner does not respond.)\n"
        "C: 'Ello, Miss?\n"
        "Owner: What do you mean 'miss'?\n"
        "C: I'm sorry, I have a cold. I wish to make a complaint!\n"
        "O: We're closin' for lunch.\n"
        "C: Never mind that, my lad. I wish to complain about this parrot what "
        "I purchased not half an hour ago from this very boutique.\n"
        "O: Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong "
        "with it?\n"
        "C: I'll tell you what's wrong with it, my lad. 'E's dead, that's "
        "what's wrong with it!\n"
        "O: No, no, 'e's uh,...he's resting.\n"
        "C: Look, matey, I know a dead parrot when I see one, and I'm looking "
        "at one right now.\n"
        "O: No no he's not dead, he's, he's restin'! Remarkable bird, the "
        "Norwegian Blue, idn'it, ay? Beautiful plumage!\n"
        "C: The plumage don't enter into it. It's stone dead.\n"
        "O: Nononono, no, no! 'E's resting!\n"
        "C: All right then, if he's restin', I'll wake him up!\n"
        "(shouting at the cage)\n"
        "'Ello, Mister Polly Parrot! I've got a lovely fresh cuttle fish for "
        "you if you show...(owner hits the cage)\n"
        "O: There, he moved!\n"
        "C: No, he didn't, that was you hitting the cage!\n"
        "O: I never!!\n"
        "C: Yes, you did!\n"
        "O: I never, never did anything...\n"
        "C: (yelling and hitting the cage repeatedly) 'ELLO POLLY!!!!!\n"
        "Testing! Testing! Testing! Testing! This is your nine o'clock alarm "
        "call!\n"
        "(Takes parrot out of the cage and thumps its head on the counter. "
        "Throws it up in the air and watches it plummet to the floor.)\n"
        "C: Now that's what I call a dead parrot.\n"
        "O: No, no.....No, 'e's stunned!\n"
        "C: STUNNED?!?\n"
        "O: Yeah! You stunned him, just as he was wakin' up! Norwegian Blues "
        "stun easily, major.\n"
        "C: Um...now look...now look, mate, I've definitely 'ad enough of "
        "this. That parrot is definitely deceased, and when I purchased it not "
        "'alf an hour ago, you assured me that its total lack of movement was "
        "due to it bein' tired and shagged out following a prolonged squawk.\n"
        "O: Well, he's...he's, ah...probably pining for the fjords.\n"
        "C: PININ' for the FJORDS?!?!?!? What kind of talk is that?, look, why "
        "did he fall flat on his back the moment I got 'im home?\n"
        "O: The Norwegian Blue prefers kippin' on it's back! Remarkable bird, "
        "id'nit, squire? Lovely plumage!\n"
        "C: Look, I took the liberty of examining that parrot when I got it "
        "home, and I discovered the only reason that it had been sitting on "
        "its perch in the first place was that it had been NAILED there.\n"
        "(pause)\n"
        "O: Well, o'course it was nailed there! If I hadn't nailed that bird "
        "down, it would have nuzzled up to those bars, bent 'em apart with its "
        "beak, and VOOM! Feeweeweewee!\n"
        "C: 'VOOM'?!? Mate, this bird wouldn't 'voom' if you put four million "
        "volts through it! 'E's bleedin' demised!\n"
        "O: No no! 'E's pining!\n"
        "C: 'E's not pinin'! 'E's passed on! This parrot is no more! He has "
        "ceased to be! 'E's expired and gone to meet 'is maker!\n"
        "'E's a stiff! Bereft of life, 'e rests in peace! If you hadn't nailed "
        "'im to the perch 'e'd be pushing up the daisies!\n"
        "\n"
        "'Is metabolic processes are now 'istory! 'E's off the twig!\n"
        "\n"
        "'E's kicked the bucket, 'e's shuffled off 'is mortal coil, run down "
        "the curtain and joined the bleedin' choir invisibile!!\n"
        "THIS IS AN EX-PARROT!!\n"
        "(pause)\n"
        "O: Well, I'd better replace it, then.\n"
        "(he takes a quick peek behind the counter)\n"
        "O: Sorry squire, I've had a look 'round the back of the shop, and uh, "
        "we're right out of parrots.\n"
        "C: I see. I see, I get the picture.\n"
        "O: I got a slug.\n"
        "(pause)\n"
        "C: (sweet as sugar) Pray, does it talk?\n"
        "O: Nnnnot really.\n"
        "C: WELL IT'S HARDLY A BLOODY REPLACEMENT, IS IT?!!?!!?\n"
        "O: Look, if you go to my brother's pet shop in Bolton, he'll replace "
        "the parrot for you.\n"
        "C: Bolton, eh? Very well.\n"
        "The customer leaves.\n"
        "The customer enters the same pet shop. The owner is putting on a "
        "false moustache.\n"
        "C: This is Bolton, is it?\n"
        "O: (with a fake mustache) No, it's Ipswitch.\n"
        "C: (looking at the camera) That's inter-city rail for you.\n"
        "The customer goes to the train station.\n"
        "He addresses a man standing behind a desk marked 'Complaints'.\n"
        "C: I wish to complain, British-Railways Person.\n"
        "Attendant: I DON'T HAVE TO DO THIS JOB, YOU KNOW!!!\n"
        "C: I beg your pardon...?\n"
        "A: I'm a qualified brain surgeon! I only do this job because I like "
        "being my own boss!\n"
        "C: Excuse me, this is irrelevant, isn't it?\n"
        "A: Yeah, well it's not easy to pad these python files out to 200 "
        "lines, you know.\n"
        "C: Well, I wish to complain. I got on the Bolton train and found "
        "myself deposited here in Ipswitch.\n"
        "A: No, this is Bolton.\n"
        "C: (to the camera) The pet shop man's brother was lying!!\n"
        "A: Can't blame British Rail for that.\n"
        "C: In that case, I shall return to the pet shop!\n"
        "He does.\n"
        "C: I understand this IS Bolton.\n"
        "O: (still with the fake mustache) Yes?\n"
        "C: You told me it was Ipswitch!\n"
        "O: ...It was a pun.\n"
        "C: (pause) A PUN?!?\n"
        "O: No, no...not a pun...What's that thing that spells the same "
        "backwards as forwards?\n"
        "C: (Long pause) A palindrome...?\n"
        "O: Yeah, that's it!\n"
        "C: It's not a palindrome! The palindrome of 'Bolton' would be "
        "'Notlob'!! It don't work!!\n"
        "O: Well, what do you want?\n"
        "C: I'm not prepared to pursue my line of inquiry any longer as I "
        "think this is getting too silly!\n"
        "Sergeant-Major: Quite agree, quite agree, too silly, far too "
        "silly...\n";

const char *const MONTY_PYTHON_PER_LINE_REQUEST =
        "FDF\r\n"
        "A customer enters a pet shop.\n"
        "Customer: 'Ello, I wish to register a complaint.\n"
        "(The owner does not respond.)\n"
        "C: 'Ello, Miss?\n"
        "Owner: What do you mean 'miss'?\n"
        "C: I'm sorry, I have a cold. I wish to make a complaint!\n"
        "O: We're closin' for lunch.\n"
        "C: Never mind that, my lad. I wish to complain about this parrot what "
        "I purchased not half an hour ago from this very boutique.\n"
        "O: Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong "
        "with it?\n"
        "C: I'll tell you what's wrong with it, my lad. 'E's dead, that's "
        "what's wrong with it!\n"
        "O: No, no, 'e's uh,...he's resting.\n"
        "C: Look, matey, I know a dead parrot when I see one, and I'm looking "
        "at one right now.\n"
        "O: No no he's not dead, he's, he's restin'! Remarkable bird, the "
        "Norwegian Blue, idn'it, ay? Beautiful plumage!\n"
        "C: The plumage don't enter into it. It's stone dead.\n"
        "O: Nononono, no, no! 'E's resting!\n"
        "C: All right then, if he's restin', I'll wake him up!\n"
        "(shouting at the cage)\n"
        "'Ello, Mister Polly Parrot! I've got a lovely fresh cuttle fish for "
        "you if you show...(owner hits the cage)\n"
        "O: There, he moved!\n"
        "C: No, he didn't, that was you hitting the cage!\n"
        "O: I never!!\n"
        "C: Yes, you did!\n"
        "O: I never, never did anything...\n"
        "C: (yelling and hitting the cage repeatedly) 'ELLO POLLY!!!!!\n"
        "Testing! Testing! Testing! Testing! This is your nine o'clock alarm "
        "call!\n"
        "(Takes parrot out of the cage and thumps its head on the counter. "
        "Throws it up in the air and watches it plummet to the floor.)\n"
        "C: Now that's what I call a dead parrot.\n"
        "O: No, no.....No, 'e's stunned!\n"
        "C: STUNNED?!?\n"
        "O: Yeah! You stunned him, just as he was wakin' up! Norwegian Blues "
        "stun easily, major.\n"
        "C: Um...now look...now look, mate, I've definitely 'ad enough of "
        "this. That parrot is definitely deceased, and when I purchased it not "
        "'alf an hour ago, you assured me that its total lack of movement was "
        "due to it bein' tired and shagged out following a prolonged squawk.\n"
        "O: Well, he's...he's, ah...probably pining for the fjords.\n"
        "C: PININ' for the FJORDS?!?!?!? What kind of talk is that?, look, why "
        "did he fall flat on his back the moment I got 'im home?\n"
        "O: The Norwegian Blue prefers kippin' on it's back! Remarkable bird, "
        "id'nit, squire? Lovely plumage!\n"
        "C: Look, I took the liberty of examining that parrot when I got it "
        "home, and I discovered the only reason that it had been sitting on "
        "its perch in the first place was that it had been NAILED there.\n"
        "(pause)\n"
        "O: Well, o'course it was nailed there! If I hadn't nailed that bird "
        "down, it would have nuzzled up to those bars, bent 'em apart with its "
        "beak, and VOOM! Feeweeweewee!\n"
        "C: 'VOOM'?!? Mate, this bird wouldn't 'voom' if you put four million "
        "volts through it! 'E's bleedin' demised!\n"
        "O: No no! 'E's pining!\n"
        "C: 'E's not pinin'! 'E's passed on! This parrot is no more! He has "
        "ceased to be! 'E's expired and gone to meet 'is maker!\n"
        "'E's a stiff! Bereft of life, 'e rests in peace! If you hadn't nailed "
        "'im to the perch 'e'd be pushing up the daisies!\n"
        "\n"
        "'Is metabolic processes are now 'istory! 'E's off the twig!\n"
        "\n"
        "'E's kicked the bucket, 'e's shuffled off 'is mortal coil, run down "
        "the curtain and joined the bleedin' choir invisibile!!\n"
        "THIS IS AN EX-PARROT!!\n"
        "(pause)\n"
        "O: Well, I'd better replace it, then.\n"
        "(he takes a quick peek behind the counter)\n"
        "O: Sorry squire, I've had a look 'round the back of the shop, and uh, "
        "we're right out of parrots.\n"
        "C: I see. I see, I get the picture.\n"
        "O: I got a slug.\n"
        "(pause)\n"
        "C: (sweet as sugar) Pray, does it talk?\n"
        "O: Nnnnot really.\n"
        "C: WELL IT'S HARDLY A BLOODY REPLACEMENT, IS IT?!!?!!?\n"
        "O: Look, if you go to my brother's pet shop in Bolton, he'll replace "
        "the parrot for you.\n"
        "C: Bolton, eh? Very well.\n"
        "The customer leaves.\n"
        "The customer enters the same pet shop. The owner is putting on a "
        "false moustache.\n"
        "C: This is Bolton, is it?\n"
        "O: (with a fake mustache) No, it's Ipswitch.\n"
        "C: (looking at the camera) That's inter-city rail for you.\n"
        "The customer goes to the train station.\n"
        "He addresses a man standing behind a desk marked 'Complaints'.\n"
        "C: I wish to complain, British-Railways Person.\n"
        "Attendant: I DON'T HAVE TO DO THIS JOB, YOU KNOW!!!\n"
        "C: I beg your pardon...?\n"
        "\r\n"
        "420\r\n"
        "A: I'm a qualified brain surgeon! I only do this job because I like "
        "being my own boss!\n"
        "C: Excuse me, this is irrelevant, isn't it?\n"
        "A: Yeah, well it's not easy to pad these python files out to 200 "
        "lines, you know.\n"
        "C: Well, I wish to complain. I got on the Bolton train and found "
        "myself deposited here in Ipswitch.\n"
        "A: No, this is Bolton.\n"
        "C: (to the camera) The pet shop man's brother was lying!!\n"
        "A: Can't blame British Rail for that.\n"
        "C: In that case, I shall return to the pet shop!\n"
        "He does.\n"
        "C: I understand this IS Bolton.\n"
        "O: (still with the fake mustache) Yes?\n"
        "C: You told me it was Ipswitch!\n"
        "O: ...It was a pun.\n"
        "C: (pause) A PUN?!?\n"
        "O: No, no...not a pun...What's that thing that spells the same "
        "backwards as forwards?\n"
        "C: (Long pause) A palindrome...?\n"
        "O: Yeah, that's it!\n"
        "C: It's not a palindrome! The palindrome of 'Bolton' would be "
        "'Notlob'!! It don't work!!\n"
        "O: Well, what do you want?\n"
        "C: I'm not prepared to pursue my line of inquiry any longer as I "
        "think this is getting too silly!\n"
        "Sergeant-Major: Quite agree, quite agree, too silly, far too "
        "silly...\n\r\n"
        "0\r\n"
        "\r\n";

AVS_UNIT_TEST(http, chunked_request) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    /* The text used in this test is 5119 bytes long.
     * This is to test writing more than buffer size, which is 4096. */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, no_100_continue) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    /* not sending 100 Continue here;
     * expecting it'll succeed anyway after timeout */
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, error_417) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 417 Expectation Failed\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_PER_LINE_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    while (*tmp_data) {
        send_line(stream, &tmp_data);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

const char *const MONTY_PYTHON_BIG_REQUEST =
        "1E\r\n"
        "A customer enters a pet shop.\n"
        "\r\n"
        "13E1\r\n"
        "Customer: 'Ello, I wish to register a complaint.\n"
        "(The owner does not respond.)\n"
        "C: 'Ello, Miss?\n"
        "Owner: What do you mean 'miss'?\n"
        "C: I'm sorry, I have a cold. I wish to make a complaint!\n"
        "O: We're closin' for lunch.\n"
        "C: Never mind that, my lad. I wish to complain about this parrot what "
        "I purchased not half an hour ago from this very boutique.\n"
        "O: Oh yes, the, uh, the Norwegian Blue...What's,uh...What's wrong "
        "with it?\n"
        "C: I'll tell you what's wrong with it, my lad. 'E's dead, that's "
        "what's wrong with it!\n"
        "O: No, no, 'e's uh,...he's resting.\n"
        "C: Look, matey, I know a dead parrot when I see one, and I'm looking "
        "at one right now.\n"
        "O: No no he's not dead, he's, he's restin'! Remarkable bird, the "
        "Norwegian Blue, idn'it, ay? Beautiful plumage!\n"
        "C: The plumage don't enter into it. It's stone dead.\n"
        "O: Nononono, no, no! 'E's resting!\n"
        "C: All right then, if he's restin', I'll wake him up!\n"
        "(shouting at the cage)\n"
        "'Ello, Mister Polly Parrot! I've got a lovely fresh cuttle fish for "
        "you if you show...(owner hits the cage)\n"
        "O: There, he moved!\n"
        "C: No, he didn't, that was you hitting the cage!\n"
        "O: I never!!\n"
        "C: Yes, you did!\n"
        "O: I never, never did anything...\n"
        "C: (yelling and hitting the cage repeatedly) 'ELLO POLLY!!!!!\n"
        "Testing! Testing! Testing! Testing! This is your nine o'clock alarm "
        "call!\n"
        "(Takes parrot out of the cage and thumps its head on the counter. "
        "Throws it up in the air and watches it plummet to the floor.)\n"
        "C: Now that's what I call a dead parrot.\n"
        "O: No, no.....No, 'e's stunned!\n"
        "C: STUNNED?!?\n"
        "O: Yeah! You stunned him, just as he was wakin' up! Norwegian Blues "
        "stun easily, major.\n"
        "C: Um...now look...now look, mate, I've definitely 'ad enough of "
        "this. That parrot is definitely deceased, and when I purchased it not "
        "'alf an hour ago, you assured me that its total lack of movement was "
        "due to it bein' tired and shagged out following a prolonged squawk.\n"
        "O: Well, he's...he's, ah...probably pining for the fjords.\n"
        "C: PININ' for the FJORDS?!?!?!? What kind of talk is that?, look, why "
        "did he fall flat on his back the moment I got 'im home?\n"
        "O: The Norwegian Blue prefers kippin' on it's back! Remarkable bird, "
        "id'nit, squire? Lovely plumage!\n"
        "C: Look, I took the liberty of examining that parrot when I got it "
        "home, and I discovered the only reason that it had been sitting on "
        "its perch in the first place was that it had been NAILED there.\n"
        "(pause)\n"
        "O: Well, o'course it was nailed there! If I hadn't nailed that bird "
        "down, it would have nuzzled up to those bars, bent 'em apart with its "
        "beak, and VOOM! Feeweeweewee!\n"
        "C: 'VOOM'?!? Mate, this bird wouldn't 'voom' if you put four million "
        "volts through it! 'E's bleedin' demised!\n"
        "O: No no! 'E's pining!\n"
        "C: 'E's not pinin'! 'E's passed on! This parrot is no more! He has "
        "ceased to be! 'E's expired and gone to meet 'is maker!\n"
        "'E's a stiff! Bereft of life, 'e rests in peace! If you hadn't nailed "
        "'im to the perch 'e'd be pushing up the daisies!\n"
        "\n"
        "'Is metabolic processes are now 'istory! 'E's off the twig!\n"
        "\n"
        "'E's kicked the bucket, 'e's shuffled off 'is mortal coil, run down "
        "the curtain and joined the bleedin' choir invisibile!!\n"
        "THIS IS AN EX-PARROT!!\n"
        "(pause)\n"
        "O: Well, I'd better replace it, then.\n"
        "(he takes a quick peek behind the counter)\n"
        "O: Sorry squire, I've had a look 'round the back of the shop, and uh, "
        "we're right out of parrots.\n"
        "C: I see. I see, I get the picture.\n"
        "O: I got a slug.\n"
        "(pause)\n"
        "C: (sweet as sugar) Pray, does it talk?\n"
        "O: Nnnnot really.\n"
        "C: WELL IT'S HARDLY A BLOODY REPLACEMENT, IS IT?!!?!!?\n"
        "O: Look, if you go to my brother's pet shop in Bolton, he'll replace "
        "the parrot for you.\n"
        "C: Bolton, eh? Very well.\n"
        "The customer leaves.\n"
        "The customer enters the same pet shop. The owner is putting on a "
        "false moustache.\n"
        "C: This is Bolton, is it?\n"
        "O: (with a fake mustache) No, it's Ipswitch.\n"
        "C: (looking at the camera) That's inter-city rail for you.\n"
        "The customer goes to the train station.\n"
        "He addresses a man standing behind a desk marked 'Complaints'.\n"
        "C: I wish to complain, British-Railways Person.\n"
        "Attendant: I DON'T HAVE TO DO THIS JOB, YOU KNOW!!!\n"
        "C: I beg your pardon...?\n"
        "A: I'm a qualified brain surgeon! I only do this job because I like "
        "being my own boss!\n"
        "C: Excuse me, this is irrelevant, isn't it?\n"
        "A: Yeah, well it's not easy to pad these python files out to 200 "
        "lines, you know.\n"
        "C: Well, I wish to complain. I got on the Bolton train and found "
        "myself deposited here in Ipswitch.\n"
        "A: No, this is Bolton.\n"
        "C: (to the camera) The pet shop man's brother was lying!!\n"
        "A: Can't blame British Rail for that.\n"
        "C: In that case, I shall return to the pet shop!\n"
        "He does.\n"
        "C: I understand this IS Bolton.\n"
        "O: (still with the fake mustache) Yes?\n"
        "C: You told me it was Ipswitch!\n"
        "O: ...It was a pun.\n"
        "C: (pause) A PUN?!?\n"
        "O: No, no...not a pun...What's that thing that spells the same "
        "backwards as forwards?\n"
        "C: (Long pause) A palindrome...?\n"
        "O: Yeah, that's it!\n"
        "C: It's not a palindrome! The palindrome of 'Bolton' would be "
        "'Notlob'!! It don't work!!\n"
        "O: Well, what do you want?\n"
        "C: I'm not prepared to pursue my line of inquiry any longer as I "
        "think this is getting too silly!\n"
        "Sergeant-Major: Quite agree, quite agree, too silly, far too "
        "silly...\n\r\n"
        "0\r\n"
        "\r\n";

AVS_UNIT_TEST(http, big_chunked_request) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://python.monty/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "python.monty", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: python.monty\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Expect: 100-continue\r\n"
               "Transfer-Encoding: chunked\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 100 Continue\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_BIG_REQUEST;
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    tmp_data = MONTY_PYTHON_RAW;
    send_line(stream, &tmp_data);
    AVS_UNIT_ASSERT_SUCCESS(
            avs_stream_write(stream, tmp_data, strlen(tmp_data)));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, redirect) {
    const char *tmp_data = NULL;
    size_t i;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *sockets[6];
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.nyan.cat/");
    memset(sockets, 0, sizeof(sockets));
    AVS_UNIT_ASSERT_NOT_NULL(client);
    for (i = 0; i < 6; ++i) {
        avs_unit_mocksock_create(&sockets[i]);
    }
    avs_http_test_expect_create_socket(sockets[0], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[0], "www.nyan.cat", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.nyan.cat\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[0], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 302 Found\r\n"
               "Location: http://www.poteflon.pl/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[0], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[1], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[1], "www.poteflon.pl", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.poteflon.pl\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[1], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 307 Temporary Redirect\r\n"
               "Location: http://htf.atom.com/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[1], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[2], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[2], "htf.atom.com", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: htf.atom.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[2], tmp_data, strlen(tmp_data));

    tmp_data = "HTTP/1.1 301 Moved Permanently\r\n"
               "Location: http://www.youtube.com/watch?v=dQw4w9WgXcQ\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[2], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[3], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[3], "www.youtube.com", "80");
    tmp_data = "GET /watch?v=dQw4w9WgXcQ HTTP/1.1\r\n"
               "Host: www.youtube.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[3], tmp_data, strlen(tmp_data));

    tmp_data = "HTTP/1.1 302 Found\r\n"
               "Location: http://isnickelbacktheworstbandever.tumblr.com/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[3], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[4], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(
            sockets[4], "isnickelbacktheworstbandever.tumblr.com", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: isnickelbacktheworstbandever.tumblr.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[4], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 307 Temporary Redirect\r\n"
               "Location: http://www.badumtss.net/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[4], tmp_data, strlen(tmp_data));

    avs_http_test_expect_create_socket(sockets[5], AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(sockets[5], "www.badumtss.net", "80");
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.badumtss.net\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "\r\n";
    avs_unit_mocksock_expect_output(sockets[5], tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 301 Moved Permanently\r\n"
               "Location: http://www.randomwebsite.com/\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(sockets[5], tmp_data, strlen(tmp_data));

    avs_error_t err = avs_stream_finish_message(stream);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_HTTP_ERROR_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, 301);
    AVS_UNIT_ASSERT_EQUAL(avs_http_status_code(stream), 301);
    avs_unit_mocksock_assert_io_clean(sockets[5]);
    avs_unit_mocksock_expect_shutdown(sockets[5]);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, interleaving) {
    const char *tmp_data = NULL;
    char buffer[64];
    bool message_finished = false;
    size_t i;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://pudim.com.br/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "pudim.com.br", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: pudim.com.br\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "\r\n"
               "'Twas brillig, and the slithy toves\n"
               "Did gyre and gimble in the wabe;\n"
               "All mimsy were the borogoves,\n"
               "And the mome raths outgrabe.\n"
               "\n"
               "\"Beware the Jabberwock, my son!\n"
               "The jaws that bite, the claws that catch!\n"
               "Beware the Jubjub bird, and shun\n"
               "The frumious Bandersnatch!\"\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished,
                                               buffer, sizeof(buffer)));
    for (i = 0; buffer[i]; ++i) {
        buffer[i] = (char) toupper(buffer[i]);
    }
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "%s\n", buffer));
    while (!message_finished) {
        avs_error_t err = avs_stream_getline(stream, NULL, &message_finished,
                                             buffer, sizeof(buffer));
        AVS_UNIT_ASSERT_TRUE(avs_is_ok(err) || message_finished);
        if (message_finished) {
            break;
        }
        for (i = 0; buffer[i]; ++i) {
            buffer[i] = (char) toupper(buffer[i]);
        }
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_write_f(stream, "%s\n", buffer));
    }
    avs_unit_mocksock_assert_io_clean(socket);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: pudim.com.br\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 264\r\n"
               "\r\n"
               "'TWAS BRILLIG, AND THE SLITHY TOVES\n"
               "DID GYRE AND GIMBLE IN THE WABE;\n"
               "ALL MIMSY WERE THE BOROGOVES,\n"
               "AND THE MOME RATHS OUTGRABE.\n"
               "\n"
               "\"BEWARE THE JABBERWOCK, MY SON!\n"
               "THE JAWS THAT BITE, THE CLAWS THAT CATCH!\n"
               "BEWARE THE JUBJUB BIRD, AND SHUN\n"
               "THE FRUMIOUS BANDERSNATCH!\"\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_expect_mid_close(socket);
    avs_unit_mocksock_expect_connect(socket, "pudim.com.br", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, interleaving_error) {
    const char *tmp_data = NULL;
    char buffer[64];
    bool message_finished = false;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.omfgdogs.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.omfgdogs.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_POST,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "POST / HTTP/1.1\r\n"
               "Host: www.omfgdogs.com\r\n"
#ifdef AVS_COMMONS_HTTP_WITH_ZLIB
               "Accept-Encoding: gzip, deflate\r\n"
#endif
               "Content-Length: 0\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    // Note that Content-Length is larger than the data provided
    tmp_data =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4981\r\n"
            "\r\n"
            "Far far away, behind the word mountains, far from the countries\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_getline(stream, NULL, &message_finished,
                                               buffer, sizeof(buffer)));
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, send_headers_fail) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://www.avsystem.com/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "www.avsystem.com", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: www.avsystem.com\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EIO));
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

#ifdef AVS_COMMONS_NET_WITH_IPV6
AVS_UNIT_TEST(http, ipv6_host_header_has_square_brackets) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://[::1:2:3:4]:1234/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "::1:2:3:4", "1234");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: [::1:2:3:4]:1234\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_output_fail(socket, avs_errno(AVS_EIO));
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}
#endif // AVS_COMMONS_NET_WITH_IPV6

AVS_UNIT_TEST(http, invalid_uri_protocol) {
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_url_t *url = avs_url_parse("coap://127.0.0.1");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    avs_error_t err =
            avs_http_open_stream(&(avs_stream_t *) { NULL }, client,
                                 AVS_HTTP_GET, AVS_HTTP_CONTENT_IDENTITY, url,
                                 NULL, NULL);
    AVS_UNIT_ASSERT_FAILED(err);
    AVS_UNIT_ASSERT_EQUAL(err.category, AVS_ERRNO_CATEGORY);
    AVS_UNIT_ASSERT_EQUAL(err.code, AVS_EINVAL);
    avs_url_free(url);
    avs_http_free(client);
}

#ifdef AVS_COMMONS_HTTP_WITH_ZLIB

#    define MONTY_PYTHON_DEFLATED                                              \
        "\x7d\x58\xcb\x72\xdb\xb8\x16\xdc\xeb\x2b\xc0\x15\xed\x2a\x45\x35\x35" \
        "\xcb\x6c\x5c\xf2\x63\x2a\x9a\xeb\x48\x1e\xdb\x49\xae\x97\x90\x08\x8a" \
        "\x88\x48\x82\x01\x48\x33\x9a\xaf\xbf\xdd\x07\xd0\xc3\x4e\xea\x26\x4e" \
        "\x4c\x11\xaf\xf3\xe8\xee\x73\xa0\xb9\xda\x0c\xa1\x77\x8d\xf1\xca\xb4" \
        "\xbd\xf1\x41\x69\xd5\x99\x5e\x85\xca\x75\xb3\xc9\x4d\x1a\xfb\xa8\xf2" \
        "\xbb\xba\x76\x53\xb5\x50\xa3\x0d\x95\xea\x9d\xf2\x66\x6b\x03\x16\x60" \
        "\xfe\xc6\x35\x5d\xad\x6d\xdb\xcf\x26\x17\xcf\x95\x51\x6e\x6c\xf1\xbe" \
        "\x70\x26\xa8\xd6\xf5\x98\x19\x3a\xd7\x16\xb3\xcb\xc9\xcd\x71\x9f\xcf" \
        "\x36\x84\xab\xc9\x8a\x13\x3f\xaa\x6f\x95\xee\x31\x5d\xed\xdd\xa0\x1a" \
        "\xa3\x5b\x95\x37\x18\xce\xaf\x38\x7f\x91\x37\x2a\x38\xef\xf7\x3c\xbb" \
        "\xd2\xaf\x46\xce\xab\x8b\xd9\x99\x29\x8d\xde\x99\x73\x33\xb2\xc9\x0a" \
        "\x9b\x9a\xdc\x1b\xb5\xa9\x5d\xb0\x6d\xae\x4a\xe7\x55\x3d\xb4\x9b\x6a" \
        "\xc6\x4d\x97\xe6\x15\x06\x36\xb6\x2d\x54\x8f\xb3\xa7\xaa\xd9\xab\x5a" \
        "\xbf\xd9\xf3\xb0\x99\xd2\x6b\x37\xf4\x98\x66\x83\xea\xb4\xf7\xf0\x67" \
        "\xa4\xb9\x0b\xd5\x0d\x7e\x53\xe9\x60\x0a\x71\xb2\xd2\x75\xa9\x60\x7a" \
        "\xe5\x06\x84\x64\xeb\x54\xe9\x5d\x13\x97\xe1\xac\xbd\xe2\x2e\xf6\xc7" \
        "\x60\x66\xb4\x6d\x55\xa9\xbd\x09\x53\x0c\x9b\xa9\x1a\x2a\x79\x50\x4b" \
        "\xe7\x47\xc4\x14\x7b\x5c\xd7\x98\x37\x9b\x31\x2c\x79\x98\x0e\xd5\xf1" \
        "\x59\x8d\xde\xb5\x5b\xd8\xd8\x57\xca\xf6\x29\x3e\x75\xad\x7a\x83\xff" \
        "\x18\xbd\xf1\x37\xd3\x4e\xde\xe5\x77\x18\x2b\x8c\x2e\xa6\xe2\x36\x27" \
        "\xfe\x66\xbe\x44\x6f\x89\x1c\xb5\xf8\x97\x1b\x0c\xc3\x42\x98\x50\xf1" \
        "\x11\xb9\xec\x6d\xbb\x95\x28\xde\x3b\xb7\xc3\xe6\xba\x37\x92\x9c\x5d" \
        "\xeb\x46\x64\x81\xfb\x9f\x22\x65\x5a\x8c\x04\x03\x4c\xb4\x70\x55\x23" \
        "\xe0\x4c\x68\x8d\x95\xd8\x45\x21\x8e\x78\xaf\xbc\xdd\x56\x3d\x8e\x1b" \
        "\x67\xf1\x68\x3c\x2a\x39\x8d\x81\x8d\xf6\xf2\x63\xfc\x3f\x99\x90\x67" \
        "\xea\xd1\x34\xda\xef\xf4\xba\x36\x6a\x6d\x7d\xf1\xbb\x28\x4e\x95\x2d" \
        "\xda\x9c\x31\xd0\xfb\x2b\x75\x6d\x34\x92\x50\x0e\xb5\xea\xea\xa1\xd1" \
        "\x5b\x93\xd1\x0d\x22\x36\x7d\x06\x08\xdb\xbc\x8f\x44\x50\x00\x92\x43" \
        "\x38\x00\x0a\x86\x08\x3c\x80\xa5\x34\x26\x19\xd9\xca\xdf\x18\xa5\xd6" \
        "\x65\x31\xb8\x29\x3c\xb2\xef\x1c\x39\x89\x9e\xc1\xae\x16\x96\x94\x6f" \
        "\xec\x9f\xc6\xd4\x8d\xc4\x6e\x65\x1b\x35\x74\xd9\xe4\x02\xac\x1b\xfa" \
        "\x14\x19\x7a\xb3\x81\x51\x97\x93\x13\x67\x68\xd7\x83\xab\xeb\xbd\x7a" \
        "\x90\x08\x67\xd8\x04\x94\xd8\x22\x4e\x1a\x51\x7d\x35\x18\x29\x71\x40" \
        "\x05\x56\xf7\x3d\x02\x53\x12\xce\x04\x3f\xd1\x01\x0b\xf8\x0b\x87\x8c" \
        "\xc8\xe7\x45\xa4\x69\x65\xfb\x70\x76\xd6\x4a\x02\xe2\x0d\x83\xad\x1a" \
        "\xec\x58\x88\x33\xc4\x03\x5e\x14\x0c\x67\x1f\xe1\x03\xd3\x83\xec\x87" \
        "\x1d\xc4\xe6\xc3\x26\x02\xa0\x85\x6a\x49\xb2\x4c\x56\xbf\x10\xec\x9c" \
        "\x8a\xf5\xe7\xa3\xd3\xf8\x8b\xaf\x81\x8d\x3d\xd8\x02\x68\xcd\x04\x5c" \
        "\x17\x7b\x60\x5a\x22\x01\xcc\xbc\x3f\x01\x31\xec\x0c\x70\x57\xd4\xfb" \
        "\x4b\x04\xfe\xfe\x7e\xa5\x1e\x56\xf7\xf7\x2f\x19\xff\x4c\x9e\x53\x12" \
        "\xd4\xff\x7b\x20\x31\xad\xd8\xef\x55\x6b\x91\x5a\x97\x43\x2b\x36\x3b" \
        "\xa5\x6b\xed\x1b\x9c\x52\xd7\xc8\xc7\x33\xb2\x73\xe4\x3d\x75\xc0\x95" \
        "\x27\x23\xb4\xc8\xc7\xd0\x74\xd8\x09\x31\xac\x08\x7c\xd7\xc6\x71\x37" \
        "\x10\x43\x33\x9c\xe3\xdd\xc8\x71\xe4\x17\x88\x92\x41\x6d\xbd\xac\x1d" \
        "\x75\xbf\xa9\x8c\x0c\x12\x7f\x0d\x54\x17\x88\xe3\x8c\x12\x04\xf1\x51" \
        "\x2f\x97\x20\xd5\x19\x59\x11\x39\x9a\xf6\x96\x67\xb3\x13\x63\x67\xfc" \
        "\xb3\x3c\x10\x37\xf4\x43\xdb\xa6\x0c\x3e\x3d\x7f\x59\x2e\xef\x6e\xaf" \
        "\xb2\x2b\xce\x7e\x31\xba\xca\xd4\x0b\xd1\x10\xe7\x10\x83\x53\xf5\x1d" \
        "\x7a\xaf\x34\x7d\x91\xec\x02\x9c\x14\x4f\x40\xf3\x1d\xaf\xe2\xd6\xca" \
        "\xe8\x60\xeb\x3d\x35\xe0\x3b\xec\xe5\x29\x5f\x1a\x9c\x4f\x21\x20\xc5" \
        "\xcf\x1e\xa3\x4e\x4c\x23\x5c\x0b\x53\xda\xd6\xf6\x04\x6b\x0e\x27\x4c" \
        "\xeb\x86\x6d\x15\x43\x6b\x03\x63\x06\x3f\x53\xcc\x6d\x38\x9f\x5d\x98" \
        "\x8d\xa1\xe2\x46\x25\x49\xea\x72\xd2\x61\xdb\x8b\x62\xe4\xef\xa4\x38" \
        "\x42\x4f\x87\x30\x78\x4c\x6a\x4c\x44\xaf\xc0\xde\xf5\xba\x86\x36\x22" \
        "\xed\x38\x9d\x68\x6f\xc0\x7d\x71\xbd\x18\x8c\x12\xfe\xab\xb5\x61\x0c" \
        "\x7a\xcb\xc5\x3c\x36\x54\x7a\xbb\xc5\x33\xe1\x50\x82\x8b\x6e\x14\x98" \
        "\xaa\xce\xbb\x1a\x32\x8a\x91\xf0\x63\xd0\xe3\x6e\x16\xab\x50\x5d\x47" \
        "\xdd\x4a\x0a\x0a\xd3\xa9\xe7\x98\xbc\x86\x72\xed\x55\x07\xdf\xb0\x9c" \
        "\x14\x95\xcc\x23\x90\x45\x90\x50\x3e\x2c\x96\x8b\x65\x7e\x1c\xf9\xeb" \
        "\xef\xd5\xe3\xed\x13\xd2\xc7\xbf\xb1\x64\xee\x58\xc0\x18\x36\x5d\xef" \
        "\x18\x29\xfa\x75\x35\x4d\xf1\x1e\xab\xbd\xf0\x8a\x9b\x12\x31\x65\x2d" \
        "\x6a\xab\x08\xfc\x35\x3d\xee\x85\xe0\xe2\xf0\x42\x14\x24\x87\x0a\x55" \
        "\x78\x71\x95\x44\xe0\x5d\xce\xe1\xa0\x29\xd9\x20\xec\x6c\xd7\x31\x24" \
        "\xd8\xcc\x12\x97\xdc\xed\x37\x6a\x6c\x8b\xbc\xa5\xf2\x22\x1a\x88\xdd" \
        "\x15\xca\x85\xc8\xd3\xb9\xf4\xc6\x0a\xb2\x40\xa0\x5d\xb4\xa7\xb6\x6b" \
        "\xe3\xfb\x3d\x9d\x32\x3f\x75\x13\x63\xd3\x9f\xe1\x21\xe5\x9c\xe6\x22" \
        "\x35\xb4\x36\x55\x15\xf8\x1a\x36\x38\x81\x59\xe2\x4e\xae\xc5\x59\x1e" \
        "\x68\x11\x46\xea\x38\x1d\x60\x5b\x1b\x6c\x10\x92\x9e\x88\x07\xe0\xb7" \
        "\x01\x82\x0e\xec\x2c\xad\x0f\x24\xa4\xde\x44\x0e\xfc\xb2\x78\x39\x5f" \
        "\xdc\xdf\xdd\x72\xae\x47\x35\xbf\xe8\xf4\x10\xa2\x6e\xc6\x5c\x43\x47" \
        "\x80\xbb\x60\xb8\x86\xeb\x5b\x6d\xeb\x68\x93\x37\x90\xeb\x52\xda\x18" \
        "\xaa\xe8\x69\x04\x07\x30\x64\xa8\x3e\x23\xeb\x04\xd6\xb9\xa1\x2e\x62" \
        "\xb7\xd3\x0e\xff\xfe\xcb\x59\x90\x0f\x11\x07\x87\x9d\xd7\xda\x03\x47" \
        "\x6b\x66\x2e\x37\x8d\xd2\x88\x4d\x7f\xa8\xde\x48\x87\xd1\xbb\x18\x94" \
        "\xaf\xab\xd5\xe7\x4c\xfd\x65\xcc\x78\xf8\x91\xa8\xe7\x7c\x9f\x13\x45" \
        "\x9f\x85\x93\xd2\xa4\x88\x01\x72\x2e\x4d\xcb\x5f\x9d\x6b\xf2\x43\xc1" \
        "\xe8\x04\xe9\x03\x3b\x26\x68\x32\x82\xf6\xea\x6a\x29\x1a\x5e\x88\x8b" \
        "\x96\x21\x56\x3f\xe4\xde\x14\x44\x46\x61\xd0\xc0\x99\x22\x3b\x96\xf3" \
        "\x34\x21\x82\x3d\x1a\x71\x97\xea\xbb\xbc\xcb\x0f\x13\xc0\x52\x52\xab" \
        "\x4d\x0a\x7d\x52\x01\xb4\x04\x8d\x63\x04\x3f\xa1\x5c\x22\xac\x51\x08" \
        "\x18\x93\xb5\x49\x8b\xcd\xcf\xee\x48\xd2\x2d\xab\x35\x5b\x43\x63\x08" \
        "\xec\x20\x3d\xa2\xcf\x26\x32\x51\x43\xbd\x6c\x59\x66\x68\x08\x00\x69" \
        "\x11\xf5\xda\x96\x86\xa2\x29\xd5\x39\x10\x0b\x28\x30\x9b\x98\x30\xa9" \
        "\x71\x6f\x52\x46\xa6\x24\xa9\x8e\xd8\x81\xda\x12\x1d\x88\x54\x60\x0d" \
        "\x93\x6c\xb1\x5c\x6a\x1b\xac\x09\xd9\x64\x92\x2f\x60\x82\xe9\xd1\x4c" \
        "\xd6\x76\x43\xa9\xd8\x18\x78\x0a\x53\xd0\xa3\x52\x23\x61\x62\xef\xfc" \
        "\x3e\x79\xe2\xca\x58\x66\xfa\xd1\x6e\xb9\x98\xef\x76\x76\xb3\x4b\xd8" \
        "\x5e\x0f\x78\xec\x0f\x1a\x5f\x0d\x65\x49\xa3\xb8\x48\x3c\x75\x9e\xaa" \
        "\xb6\x71\x16\x68\xf4\x50\x69\xc2\x2a\x56\xa5\x01\x23\x6c\x69\x11\xa0" \
        "\xef\xce\xb6\x87\xed\x0e\x69\xdb\x54\xce\xb2\xef\x79\x85\xd5\x6b\x38" \
        "\xca\x5a\xfa\x69\xf1\xa4\xf0\x33\x5f\xaa\xbb\xff\x7e\x78\x98\x3f\x3e" \
        "\xae\x9e\xf1\xfa\x17\xd4\x2f\xc4\xff\x9e\xfd\x09\x6a\xb3\x90\xc7\x4a" \
        "\x9f\x60\x5a\x70\x84\xae\x48\x25\xd5\x0a\x62\x00\xed\xe9\x8c\xd9\x61" \
        "\x7e\x15\x3b\xf0\x63\xbd\x94\x0d\x9f\xd8\xed\x27\xd5\x48\x05\x83\xdc" \
        "\xd3\xa2\x6b\x2a\x07\xe6\xd2\xa2\x75\xd2\x6d\x3e\xf3\xba\x12\x41\xcf" \
        "\x76\x7a\x94\xde\x3f\x36\x5f\xa9\x6a\x47\x24\x45\x65\x95\x8e\x74\x16" \
        "\x7f\x51\x7e\xb6\x26\x76\x5b\x9d\xdd\xf4\x83\x8f\x2d\xfa\x22\x35\x55" \
        "\xa1\x1e\xb6\x27\x96\xb3\x31\x09\x23\x31\x05\x08\x86\x61\xab\xfd\xa5" \
        "\x7a\xf0\x1a\x25\x50\x6e\x3b\xa0\x2e\xb5\x58\x04\x74\xd9\xb6\xf1\xf2" \
        "\x03\xf1\xdd\xcb\xb1\xdf\xd0\xa8\xa8\xc5\x73\xfe\xa4\x3e\xcd\x1f\x6f" \
        "\xef\x5f\xd4\x5c\x5d\xdf\xaf\x56\xb7\x2f\xea\xf1\xee\xe1\x7e\x7e\x73" \
        "\xf7\xf9\x6e\xf9\x3c\x65\xb4\x17\xcf\x57\x59\xc6\x1f\x6e\x14\x45\x32" \
        "\x51\x11\x17\x0b\xa2\x1a\xf7\x09\x78\x03\x49\x21\x67\xd2\x6d\x8d\xa0" \
        "\xbd\x06\x31\x5d\x2b\x05\x87\xdd\x67\xca\x84\xf8\x16\x99\x94\x5a\x41" \
        "\xb1\xe7\x30\xd9\x54\x57\xea\x2b\xef\x28\x23\x52\x39\x9b\x3c\x0b\x52" \
        "\xd2\x9d\xb0\x36\x10\xa1\xf0\xee\x65\xba\x28\x4a\xdc\x75\x63\x4e\xf7" \
        "\x45\x75\xba\xfd\x91\xbc\xc3\x51\x65\x35\x6b\x50\x60\xbd\xc1\x1e\x1a" \
        "\x5d\xcf\x2c\x76\xde\xb1\x09\x3b\x18\xc2\x4f\xbd\xf8\x7c\x21\x6a\xc6" \
        "\x55\xe8\x8e\x9b\xb4\xe6\x52\x7a\x1c\x29\x39\x8b\x2e\x60\x46\xba\xcd" \
        "\x5d\x9c\x5d\x27\x62\x73\x06\x23\xf5\xa5\xf4\x11\x39\xb9\x0c\x6b\x3f" \
        "\x6c\x2c\xca\x8a\x07\x7d\x4f\x21\x78\xe3\xd3\x96\xf9\x4b\x9c\xee\x3d" \
        "\x59\x82\x43\x7b\x88\xdd\x6c\x02\xc5\xd1\x45\xe1\x13\x61\xa1\x24\x32" \
        "\xd6\x16\x3c\x32\x61\x98\xed\x58\xd8\x29\x56\x40\xca\xc3\xcd\xe1\x26" \
        "\x1a\xf2\x04\xb8\xf7\xd7\xca\xa9\xba\xf6\xb6\xc7\xcb\x0f\x8f\xb0\x69" \
        "\xd4\xfb\xa0\x1e\x10\x53\x1e\x37\x07\x8b\xda\x42\xb7\x3d\xd7\xdd\xae" \
        "\x96\xf9\x33\xf0\xf2\xf5\x4e\x3d\xaf\xf0\x49\x09\x21\xff\x5e\x5d\x4f" \
        "\xd5\xcb\xea\x8b\xfa\xcf\x72\xf5\x2d\x8b\x3d\xf6\x02\xb6\x6c\x63\x3f" \
        "\x8b\x5c\xe3\x22\x83\x2e\xe3\x6a\x32\x8f\x37\x68\xf2\x4e\x43\xe3\x2c" \
        "\xac\x5b\x47\xef\x06\xbf\x35\xd4\xd9\x45\x2c\x95\x85\x8b\x75\xe0\xbb" \
        "\x5b\x63\xa3\x0d\xe1\x8e\xa1\xda\x22\xfe\x6c\x80\xb6\xc4\x1c\x75\x64" \
        "\xed\x42\x90\xf3\xee\x7e\x6e\x38\xa7\x39\x14\x10\xfe\x78\x6f\x6a\xf3" \
        "\x0a\xd3\x99\x4b\xea\x25\xd3\x39\x8f\xdd\xe6\x54\xe0\x15\xd3\x47\x62" \
        "\x40\xbf\xf7\x8c\x48\xa7\x85\xcd\xd8\xaa\xc3\x05\x00\x58\x29\xa1\x3c" \
        "\x41\x68\x8b\xd1\x3f\xff\xf8\x03\x46\xb4\x87\xfb\xc3\x4e\x2e\x89\x37" \
        "\x47\xd5\xf9\x25\xae\xb3\x44\xdc\xd4\x87\x47\x64\xa5\x84\x52\x1d\x4a" \
        "\x51\x8f\x66\x1f\x0c\x7a\xc4\xc2\x74\x0e\xad\x00\x9b\x5f\x14\x02\xf2" \
        "\xe7\x84\xab\x79\xec\xa8\xfb\x37\x10\x8d\x70\x4b\x28\x39\xc1\xec\xc4" \
        "\x00\x82\x83\x85\x30\x92\x53\xea\x7f\xbd\x67\xc9\xcb\xb8\xe1\x8d\x66" \
        "\x4c\xd6\x35\x39\x93\xd2\xaf\x1e\x0f\x90\x64\x1b\x10\xc1\x92\x1a\x96" \
        "\x0d\x0a\x1c\x5d\x44\xbf\x29\x5c\x86\x34\xb5\xa7\xaa\x13\xcf\xcb\x08" \
        "\x4e\x4a\x4f\x82\x19\x9c\x03\x8a\xfa\x78\x33\x81\xd9\xc0\xca\xc1\x72" \
        "\xb2\x0a\x65\x8f\x57\x4e\x72\x4b\x5a\x9d\xb7\xec\xc2\x2d\x4d\xbe\x52" \
        "\xe0\xad\xa0\x77\xb5\xb4\xca\xa9\x89\x39\xc4\x45\x2a\x3a\x80\xb5\x88" \
        "\xaf\xd1\xf4\x0e\x29\x28\x51\x20\x21\x69\x0f\x5f\x96\xe9\x8e\x71\xbc" \
        "\x91\xb4\xa2\xa4\x9c\x7a\xfc\x22\x43\x3c\x94\xfb\x5e\x7c\x0c\x1d\x12" \
        "\x7a\x26\x29\xd4\xf6\x11\x30\x0e\x14\x5a\x84\x47\x9e\xc5\xba\x8b\x7b" \
        "\x7e\x57\x71\x3c\xae\x03\xac\xdb\xc2\x83\xc3\x82\xf7\xd5\x01\x6c\xe9" \
        "\xce\xc4\xaf\x33\x18\x99\x03\xea\xf4\xd9\x82\x2c\xa6\xee\xf8\x99\x65" \
        "\x22\x8f\xe1\xca\x53\x0b\x86\x92\x9e\x2f\x5d\x5f\xbb\x75\x9e\x81\x2a" \
        "\x7d\xfa\x82\x60\x74\x7e\x97\x65\xa7\xea\x37\x9e\x7d\x81\x35\x02\xfe" \
        "\xc7\x6f\xae\xa4\xc1\x81\x0c\x6b\x1f\x7b\x15\xdc\x55\x02\x3a\x69\x7e" \
        "\x21\x23\x77\xce\x12\xa0\x63\xa1\xdb\xf3\xfa\xab\xe4\xfa\xe0\xe9\xf1" \
        "\x42\x62\xb3\x3b\xc2\x0f\x15\x2a\x5e\x80\x9d\x43\xf3\x8a\x82\x92\x4d" \
        "\x9e\x0c\x08\x8c\xb3\x3e\x7c\xe6\xe5\xeb\xa3\xfa\x67\x00\x92\x71\xdd" \
        "\xf1\xac\x69\x3f\xce\x3f\x1c\x17\x4d\x91\x71\x7f\xfa\xc8\x9b\xf6\xff" \
        "\x00"

const char MONTY_PYTHON_ZLIB[] =
        "\x78\x9c" MONTY_PYTHON_DEFLATED "\xed\x67\xa4\x89";
const char MONTY_PYTHON_GZIP[] =
        "\x1f\x8b\x08\x00\xfe\x20\x80\x60\x00\x03" MONTY_PYTHON_DEFLATED
        "\x8e\xb5\xb0\x77\xff\x13\x00\x00";

AVS_UNIT_TEST(http, gzipped_response) {
    const char *tmp_data = NULL;
    char buffer[strlen(MONTY_PYTHON_RAW) + 1];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
               "Accept-Encoding: gzip, deflate\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "Content-Encoding: gzip\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input(socket, MONTY_PYTHON_GZIP,
                            sizeof(MONTY_PYTHON_GZIP) - 1);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                stream, &bytes_read, &message_finished, buffer_ptr,
                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(MONTY_PYTHON_RAW));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, MONTY_PYTHON_RAW);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, deflated_response) {
    const char *tmp_data = NULL;
    char buffer[strlen(MONTY_PYTHON_RAW) + 1];
    char *buffer_ptr = buffer;
    bool message_finished = false;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
               "Accept-Encoding: gzip, deflate\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 200 OK\r\n"
               "Transfer-Encoding: identity\r\n"
               "Content-Encoding: deflate\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input(socket, MONTY_PYTHON_ZLIB,
                            sizeof(MONTY_PYTHON_ZLIB) - 1);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_finish_message(stream));
    while (!message_finished) {
        size_t bytes_read;
        AVS_UNIT_ASSERT_SUCCESS(avs_stream_read(
                stream, &bytes_read, &message_finished, buffer_ptr,
                sizeof(buffer) - (buffer_ptr - buffer)));
        buffer_ptr += bytes_read;
    }
    AVS_UNIT_ASSERT_EQUAL(buffer_ptr - buffer, strlen(MONTY_PYTHON_RAW));
    *buffer_ptr = '\0';
    AVS_UNIT_ASSERT_EQUAL_STRING(buffer, MONTY_PYTHON_RAW);
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, gzipped_error) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
               "Accept-Encoding: gzip, deflate\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 404 Not Found\r\n"
               "Transfer-Encoding: identity\r\n"
               "Content-Encoding: gzip\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input(socket, MONTY_PYTHON_GZIP,
                            sizeof(MONTY_PYTHON_GZIP) - 1);
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

AVS_UNIT_TEST(http, deflated_error) {
    const char *tmp_data = NULL;
    avs_http_t *client = avs_http_new(&AVS_HTTP_DEFAULT_BUFFER_SIZES);
    avs_net_socket_t *socket = NULL;
    avs_stream_t *stream = NULL;
    avs_url_t *url = avs_url_parse("http://monty.python/");
    AVS_UNIT_ASSERT_NOT_NULL(url);
    AVS_UNIT_ASSERT_NOT_NULL(client);
    avs_unit_mocksock_create(&socket);
    avs_http_test_expect_create_socket(socket, AVS_NET_TCP_SOCKET);
    avs_unit_mocksock_expect_connect(socket, "monty.python", "80");
    AVS_UNIT_ASSERT_SUCCESS(avs_http_open_stream(&stream, client, AVS_HTTP_GET,
                                                 AVS_HTTP_CONTENT_IDENTITY, url,
                                                 NULL, NULL));
    avs_url_free(url);
    AVS_UNIT_ASSERT_NOT_NULL(stream);
    tmp_data = "GET / HTTP/1.1\r\n"
               "Host: monty.python\r\n"
               "Accept-Encoding: gzip, deflate\r\n"
               "\r\n";
    avs_unit_mocksock_expect_output(socket, tmp_data, strlen(tmp_data));
    tmp_data = "HTTP/1.1 404 Not Found\r\n"
               "Transfer-Encoding: identity\r\n"
               "Content-Encoding: deflate\r\n"
               "\r\n";
    avs_unit_mocksock_input(socket, tmp_data, strlen(tmp_data));
    avs_unit_mocksock_input(socket, MONTY_PYTHON_ZLIB,
                            sizeof(MONTY_PYTHON_ZLIB) - 1);
    AVS_UNIT_ASSERT_FAILED(avs_stream_finish_message(stream));
    avs_unit_mocksock_assert_io_clean(socket);
    avs_unit_mocksock_expect_shutdown(socket);
    AVS_UNIT_ASSERT_SUCCESS(avs_stream_cleanup(&stream));
    avs_http_free(client);
}

#endif // AVS_COMMONS_HTTP_WITH_ZLIB
