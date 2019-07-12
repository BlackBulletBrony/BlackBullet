// ==UserScript==
// @name         MLPP Minimap
// @namespace    http://tampermonkey.net/
// @version      1.1.1
// @description  My Little Pony Pixel Minimap for PixelZone.io
// @match        https://pixelzone.io/*
// @match        http://pixelzone.io/*
// @homepage     https://github.com/BlackBulletBrony/BlackBullet
// @updateURL    https://raw.githubusercontent.com/BlackBulletBrony/BlackBullet/master/MLP_Pixel_minimap.user.js
// @downloadURL  https://raw.githubusercontent.com/BlackBulletBrony/BlackBullet/master/MLP_Pixel_minimap.user.js
// @grant        none
// ==/UserScript==
//
// To the glory of Luna and the New Lunar Republic!
// Improved by the Endless Night and MLP Pixel.
//
(function() {
    Number.prototype.between = function(a, b) {
        var min = Math.min.apply(Math, [a, b]),
            max = Math.max.apply(Math, [a, b]);
        return this > min && this < max;
    };

    var cursorColors = [`black`,`gray`,`white`,`Fuchsia`,`red`,`yellow`,`lime`,`springGreen`,`aqua`,`blue`];

    var range = 25;
    var selectColor = [];
    var cursorColor = `red`,
        grid = `On`,
        sectors = `Off`,
        debug = false,
        zoom,
        map = {
            style: `New`,
            settings:{
                Old: `background-color: rgba(0, 0, 0, 0.75); color: rgb(250, 250, 250); text-align: center; line-height: 42px; vertical-align: middle; width: auto; height: auto; border-radius: 21px; padding: 6px;`,
                New: `background-color: rgba(0, 0, 0, 0.90); color: rgb(250, 250, 250); text-align: center; line-height: 42px; vertical-align: middle; width: auto; height: auto; border-radius: 1px; padding: 1px; padding-left: 1px;`
            },
            mapbg: {
                Old: `background-color: rgba(0, 0, 0, 0.75); color: rgb(250, 250, 250); text-align: center; line-height: 42px; vertical-align: middle; width: auto; height: auto; border-radius: 21px; padding: 6px;`,
                New: `background-color: rgba(0, 0, 0, 0.90); color: rgb(250, 250, 250); text-align: center; line-height: 42px; vertical-align: middle; width: auto; height: auto; border-radius: 1px; padding: 1px; padding-left: 1px;`
           },
            minimapbg: {
                Old: `position: absolute; right: 0.5em; bottom: 4.75em;`,
                New: `position: absolute; right: 0em; top: 0em;`
            }

        };

    var factions = {
        "BLaCKBuLLeT": {
            "url": "https://raw.githubusercontent.com/BlackBulletBrony/BlackBullet/master/",
            "color": "#262626",
            "type": "2"
        }
    };

    var faction = Object.keys(factions)[0];
    var canvas = $('canvas');

    //LOCAL_STORAGE
    if(!!localStorage.cursorColor)
        cursorColor = localStorage.cursorColor;
    else
        localStorage.cursorColor = cursorColor;

    if(localStorage.debug == `true`)
        debug = true;

    if(localStorage.grid == `On`)
        grid = `On`;

    if(localStorage.mapStyle == `Old`)
        map.style = `Old`;

    if(localStorage.sectors == `On`)
        sectors = `On`;

    //>---------------------------------------------------

    window.addEventListener('load', function() {
        //Regular Expression to get coordinates out of URL
        re = /(.*)\/\?p=(\-?(?:\d*)),(\-?(?:\d*))/g;
        //Regular Expression to get coordinates from cursor
        rec = /x\:(\d*) y\:(\d*)/g;
        //DOM element of the displayed X, Y variables
        coorDOM = null;
        //coordinates of the middle of the window
        x_window = 0;
        y_window = 0;
        //coordinates of cursor
        x = 0;
        y = 0;
        //list of all available templates
        template_list = null;
        zoomlevel = 5;
        //toggle options
        toggle_show = true;
        toggle_follow = true; //if minimap is following window, x_window = x and y_window = y;
        zooming_in = false;
        zooming_out = false;
        zoom_time = 50;
        //array with all loaded template-images
        image_list = [];
        counter = 0;
        //templates which are needed in the current area
        needed_templates = null;
        //Cachebreaker to force refresh
        cachebreaker = null;

        document.body.insertAdjacentHTML('afterbegin',`<style>#settingsDiv{user-select:none;}</style>`);

        var settings = document.createElement('div');
        settings.class = 'post block bc2';

        settings.innerHTML =
            `<div id = "settingsDiv" style = "width:250px;display: none; position: absolute; right: 50%; bottom: 50%;">`+
                `<div class="posy" id="posyt" style="${map.settings[map.style]}.settings[map.style]}">`+
                    `<span style = "line-height: 35px;">MLP Pixel minimap: settings</span>`+
                    `<div style = "text-align:left;line-height: 25px">`+
                        `Cursor color: <span id = "cursorColor"style = "cursor:pointer;color:${cursorColor}">${cursorColor}</span>`+
                        `<br>`+
                        `Draw grid: <span id = "grid"style = "cursor:pointer;">${grid}</span>`+
                        `<br>`+
                        `Minimap style: <span id = "mapStyle"style = "cursor:pointer;">${map.style}</span>`+
                        `<br>`+
                        `Sectors: <span id = "sectors"style = "cursor:pointer;">${sectors}</span>`+
                    `</div>`+
                `</div>`+
            `<div>`;

        document.body.appendChild(settings);

        //EVENTS

        $(`cursorColor`).onclick = () => {
            let i = cursorColors.indexOf(cursorColor);
            i++;
            if(!cursorColors[i])
                if(i >= cursorColors.length) i = 0;
                else i = cursorColors.length;

            cursorColor = cursorColors[i];
            localStorage.cursorColor = cursorColor;

            $(`cursorColor`).innerHTML = cursorColor;
            $(`cursorColor`).style.color = cursorColor
            drawCursor();
        };

        $(`grid`).onclick = () => {
            if(localStorage.grid == `Off`){
                localStorage.grid = `On`;
                grid = `On`;
            }else{
                grid = `Off`;
                localStorage.grid = `Off`;
            }
            $(`grid`).innerHTML = grid;
            drawBoard();
        };

        $(`mapStyle`).onclick = () => {
            if(map.style == `Old`){
                localStorage.mapStyle = `New`;
                map.style = `New`;
                $(`settingsDiv`).childNodes[0].style = map.settings.New;
                $(`mapbg`).style = map.mapbg.New;
                $(`minimapbg`).style = map.minimapbg.New;
            }else{
                localStorage.mapStyle = `Old`;
                map.style = `Old`;
                $(`settingsDiv`).childNodes[0].style = map.settings.Old;
                $(`mapbg`).style = map.mapbg.Old;
                $(`minimapbg`).style = map.minimapbg.Old;
            }
            $(`mapStyle`).innerHTML = map.style;
        };

        $(`sectors`).onclick = () => {
            if(sectors == `Off`){
                localStorage.sectors = `On`;
                sectors = `On`;
                $(`sectors`).innerText = `On`;
            }else{
                localStorage.sectors = `Off`;
                sectors = `Off`;
                $(`sectors`).innerText = `Off`;
            }
        };

        //>----------------------------------------------------

        settings = $('settings');

        let list = '';
        for (let name in factions)
            if (name != '') list += `<li id="' + name + '">' + '<span Style="cursor:pointer;color:' + factions[name].color + '">${name}'<span></li>`;

        var div = document.createElement('div');
        div.class = 'post block bc2';
        div.innerHTML =
            `<div id="minimapbg" style="${map.minimapbg[map.style]}">` +
                `<div class="posy" id="mapbg" style="${map.mapbg[map.style]}">` +
                    '<div id="minimap-text" style="display: none;">'+
                    '</div>' +
                    '<div id="minimap-box" style="position: relative;width:280px;height:200px">' +
                        '<canvas id="minimap" style="width: 100%; height: 100%;z-index:1;position:absolute;top:0;left:0;"></canvas>' +
                        '<canvas id="minimapCover" style="width: 100%; height: 100%;z-index:2;position:absolute;top:0;left:0;opacity:0.5;"></canvas>' +
                        '<canvas id="minimap-board" style="width: 100%; height: 100%;z-index:2;position:absolute;top:0;left:0;"></canvas>' +
                        '<canvas id="minimap-cursor" style="width: 100%; height: 100%;z-index:3;position:absolute;top:0;left:0;"></canvas>' +
                    '</div><div id="minimap-config" style="line-height:15px;">' +
                    '<span id="hide-map" style="cursor:pointer;font-weight:bold;color: rgb(250, 0, 0);"> OFF' +
                    '</span> | <span id="follow-mouse" style="cursor:pointer;"Follow the mouse' +
                    '</span> | Zoom: <span id="zoom-plus" style="cursor:pointer;font-weight:bold;color: rgb(0, 100, 250);">+</span>  /  ' +
                    '<span id="zoom-minus" style="cursor:pointer;font-weight:bold;color: rgb(0, 50, 250);">-</span>' +
                    '<div id = "settings" style = "display:none">'+
                        '<ul id="list" style="line-height:20px;text-align:left;">' +
                            list +
                        '</ul>' +
                    '<div>'+
                '</div>' +
            '</div>';
        document.body.appendChild(div);

        minimap = $("minimap");
        minimapCover = $(`minimapCover`)
        minimap_board = $("minimap-board");
        minimap_cursor = $("minimap-cursor");
        minimap.width = minimap.offsetWidth;
        minimap_board.width = minimap_board.offsetWidth;
        minimap_cursor.width = minimap_cursor.offsetWidth;
        minimap.height = minimap.offsetHeight;
        minimap_board.height = minimap_board.offsetHeight;
        minimap_cursor.height = minimap_cursor.offsetHeight;

        minimapCover.width = minimap.width;
        minimapCover.height = minimap.height;

        ctx_minimap = minimap.getContext("2d");
        ctx_minimapCover = minimapCover.getContext(`2d`);
        ctx_minimap_board = minimap_board.getContext("2d");
        ctx_minimap_cursor = minimap_cursor.getContext("2d");

        //No Antialiasing when scaling!
        ctx_minimap.mozImageSmoothingEnabled = false;
        ctx_minimap.webkitImageSmoothingEnabled = false;
        ctx_minimap.msImageSmoothingEnabled = false;
        ctx_minimap.imageSmoothingEnabled = false;

        ctx_minimapCover.mozImageSmoothingEnabled = false;
        ctx_minimapCover.webkitImageSmoothingEnabled = false;
        ctx_minimapCover.msImageSmoothingEnabled = false;
        ctx_minimapCover.imageSmoothingEnabled = false;

        let lif = new XMLHttpRequest();
        lif.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
                factions = JSON.parse(this.responseText);
                if (debug) console.log(this.responseText);

                if ((localStorage.getItem('faction') == null) || (factions[localStorage.getItem('faction')] == undefined))
                    faction = Object.keys(factions)[0];
                else
                    faction = localStorage.getItem('faction');

                updateloop();

                let ul = $('list');
                let list = '';
                for (let name in factions)
                    if (name != "")
                        list += `<li id="${name}"><span Style="cursor:pointer;color:${factions[name].color}">${name}<span></li>`;
                ul.innerHTML = list;
                for (let name in factions)
                    $(name).onclick = function() {
                        changeDisplay('settings');
                        faction = name;
                        localStorage.setItem('faction', name);
                        updateloop();
                    };
            }
        };
        lif.open("GET", 'https://raw.githubusercontent.com/BlackBulletBrony/BlackBullet/master/factions.json', true);
        lif.send();

        drawCursor();
        drawBoard();

        $("hide-map").onclick = function() {
            toggle_show = false;
            $("minimap-box").style.display = "none";
            $("minimap-config").style.display = "none";
            $("minimap-text").style.display = "block";
            $("minimap-text").innerHTML = "Minimap";
            $("minimap-text").style.cursor = "pointer";
        };
        $("minimap-text").onclick = function() {
            toggle_show = true;
            $("minimap-box").style.display = "block";
            $("minimap-config").style.display = "block";
            $("minimap-text").style.display = "none";
            $("minimap-text").style.cursor = "default";
            loadTemplates();
        };
        $("zoom-plus").addEventListener('mousedown', function(e) {
            e.preventDefault();
            zooming_in = true;
            zooming_out = false;
            zoomIn();
        }, false);
        $("zoom-minus").addEventListener('mousedown', function(e) {
            e.preventDefault();
            zooming_out = true;
            zooming_in = false;
            zoomOut();
        }, false);
        $("zoom-plus").addEventListener('mouseup', function(e) {
            zooming_in = false;
        }, false);
        $("zoom-minus").addEventListener('mouseup', function(e) {
            zooming_out = false;
        }, false);

        canvas.addEventListener('mouseup', function(evt) {
            if (!toggle_show)
                return;
            if (!toggle_follow)
                setTimeout(getCenter, 100);
        }, false);


        canvas.addEventListener('mousemove', function(evt) {
            if (!toggle_show)
                return;
            coorDOM = $("coords");
            coordsXY = coorDOM.innerHTML.split(/(\d+)/)
            //console.log(coordsXY);
            x_new = +(coordsXY[0].substring(2) + coordsXY[1])
            y_new = +(coordsXY[2].substring(3) + coordsXY[3]);
            //console.log({x_new,y_new});
            if (x != x_new || y != y_new) {
                x = parseInt(x_new);
                y = parseInt(y_new);
                if (toggle_follow) {
                    x_window = x;
                    y_window = y;
                } else {
                    drawCursor();
                }
                loadTemplates();
            }
        }, false);

        updateloop();

    }, false);


    function updateloop() {
        if (debug) console.log("Updating Template List");
        // Get JSON of available templates
        var xmlhttp = new XMLHttpRequest();
        let url = undefined;

        if (factions[faction].templates == 'own') {
            if (factions[faction].type == 2)
                url = factions[faction].url + 'templates/data.json';
            else
                url = factions[faction].url + 'templates/data.json?' + new Date().getTime();
        } else {
            if (faction == 'BLaCKBuLLeT')
                url = factions['BLaCKBuLLeT'].url + 'templates/data.json';
            else
                url = factions['BLaCKBuLLeT'].url + 'templates/' + faction + '.json';
        }

        xmlhttp.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
                json_upl = true;
                template_list = JSON.parse(this.responseText);

                for(let name in template_list){
                    template_list[name].x = parseInt(template_list[name].x);
                    template_list[name].y = parseInt(template_list[name].y);
                    template_list[name].width = parseInt(template_list[name].width);
                    template_list[name].height = parseInt(template_list[name].height);
                };

                if (!toggle_follow)
                    getCenter();
            }
        };
        xmlhttp.open("GET", url, true);
        xmlhttp.send();

        if (debug) console.log("Refresh got forced.");
        image_list = [];
        loadTemplates();

        setTimeout(updateloop, 60000)
    }

    function toggleShow() {
        toggle_show = !toggle_show;
        if (toggle_show) {
            $("minimap-box").style.display = "block";
            $("minimap-config").style.display = "block";
            $("minimap-text").style.display = "none";
            $("minimapbg").onclick = function() {};
            loadTemplates();
        } else {
            $("minimap-box").style.display = "none";
            $("minimap-config").style.display = "none";
            $("minimap-text").style.display = "block";
            $("minimap-text").innerHTML = "Minimap";
            $("minimapbg").onclick = function() {
                toggleShow()
            };
        }
    }

    function zoomIn() {
        if (!zooming_in)
            return;
        zoomlevel = zoomlevel * 1.1;
        if (zoomlevel > 45) {
            zoomlevel = 45;
            return;
        }
        drawBoard();
        drawCursor();
        loadTemplates();
        setTimeout(zoomIn, zoom_time);
    }

    function zoomOut() {
        if (!zooming_out)
            return;
        zoomlevel = zoomlevel / 1.1;
        if (zoomlevel < 1) {
            zoomlevel = 1;
            return;
        }
        drawBoard();
        drawCursor();
        loadTemplates();
        setTimeout(zoomOut, zoom_time);
    }

    function loadTemplates() {
        if ((!toggle_show)||(template_list == null))
            return;

        var x_left = x_window - minimap.width / zoomlevel / 2;
        var x_right = x_window + minimap.width / zoomlevel / 2;
        var y_top = y_window - minimap.height / zoomlevel / 2;
        var y_bottom = y_window + minimap.height / zoomlevel / 2;

        var keys = [];

        for (var k in template_list)
            keys.push(k);

        needed_templates = [];

        for (let i = 0; i < keys.length; i++) {
            template = keys[i];

            var temp_x = template_list[template].x;
            var temp_y = template_list[template].y;
            var temp_xr = template_list[template].x + template_list[template].width;
            var temp_yb = template_list[template].y + template_list[template].height;

            if ((!x_window.between(temp_x - range, temp_xr + range))||(!y_window.between(temp_y - range, temp_yb + range)))
                continue;

            needed_templates.push(template);
        }
        if (needed_templates.length == 0) {
            if (zooming_in == false && zooming_out == false) {
                $("minimap-box").style.display = "none";
                $("minimap-text").style.display = "block";
                $("minimap-text").innerHTML = "There's nothing here.";
            }
        } else {
            $("minimap-box").style.display = "block";
            $("minimap-text").style.display = "none";
            counter = 0;
            for (i = 0; i < needed_templates.length; i++) {
                if (image_list[needed_templates[i]] == null) {
                    loadImage(needed_templates[i]);
                } else {
                    counter++;
                    //if last needed image loaded, start drawing
                    if (counter == needed_templates.length)
                        drawTemplates();
                }
            }
        }
    }

    function loadImage(imagename) {
        if (debug) console.log("    Load image " + imagename);
        image_list[imagename] = new Image();

        image_list[imagename].src = factions[faction].url + "images/" + template_list[imagename].name;

        image_list[imagename].onload = function() {
            counter++;

            if(template_list[imagename].type != `grid`)
                My_imagename = imagename;

            if (counter == needed_templates.length)
                drawTemplates();
        }
    }

    function drawTemplates(){
        ctx_minimap.clearRect(0, 0, minimap.width, minimap.height);
        ctx_minimapCover.clearRect(0, 0, minimapCover.width, minimapCover.height);

        var x_left = x_window - minimap.width / zoomlevel / 2,
            y_top = y_window - minimap.height / zoomlevel / 2,
            pictureShift = 1;

        for (var i = 0; i < needed_templates.length; i++) {
            if(template_list[needed_templates[i]].type == `grid`)
                continue;
            var template = needed_templates[i];
            var img = image_list[template];
            ctx_minimap.drawImage(image_list[template], ((template_list[template].x - x_left) * zoomlevel), ((template_list[template].y - y_top) * zoomlevel), (zoomlevel * image_list[template].width), (zoomlevel * image_list[template].height));
        }

        if(sectors == `Off`)
            return;
        for (let i = 0; i < needed_templates.length; i++) {
            if(template_list[needed_templates[i]].type != `grid`)
                continue;
            let gTemplate = needed_templates[i];
            ctx_minimapCover.drawImage(image_list[gTemplate], ((template_list[gTemplate].x - x_left) * zoomlevel * pictureShift ), ((template_list[gTemplate].y - y_top) * zoomlevel * pictureShift ), (zoomlevel * pictureShift  * image_list[gTemplate].width), (zoomlevel * pictureShift  * image_list[gTemplate].height));
        }
    }

    function drawBoard() {
    ctx_minimap_board.clearRect(0, 0, minimap_board.width, minimap_board.height);
    if ((grid == `Off`)||(zoomlevel <= 4.6))
        return;
    ctx_minimap_board.beginPath();
    var bw = minimap_board.width + zoomlevel;
    var bh = minimap_board.height + zoomlevel;
    var xoff_m = (minimap.width / 2) % zoomlevel - zoomlevel;
    var yoff_m = (minimap.height / 2) % zoomlevel - zoomlevel;
    var z = zoomlevel;

    for (var x = 0; x <= bw; x += z) {
        ctx_minimap_board.moveTo(x + xoff_m, yoff_m);
        ctx_minimap_board.lineTo(x + xoff_m, bh + yoff_m);
    }

    for (var x = 0; x <= bh; x += z) {
        ctx_minimap_board.moveTo(xoff_m, x + yoff_m);
        ctx_minimap_board.lineTo(bw + xoff_m, x + yoff_m);
    }
    ctx_minimap_board.strokeStyle = "black";
    ctx_minimap_board.stroke();
}

    function drawCursor() {
        var x_left = x_window - minimap.width / zoomlevel / 2;
        var x_right = x_window + minimap.width / zoomlevel / 2;
        var y_top = y_window - minimap.height / zoomlevel / 2;
        var y_bottom = y_window + minimap.height / zoomlevel / 2;
        ctx_minimap_cursor.clearRect(0, 0, minimap_cursor.width, minimap_cursor.height);
        if (x < x_left || x > x_right || y < y_top || y > y_bottom)return;
        xoff_c = x - x_left;
        yoff_c = y - y_top;

        ctx_minimap_cursor.beginPath();
        ctx_minimap_cursor.lineWidth = zoomlevel / 3;
        ctx_minimap_cursor.strokeStyle = cursorColor;
        ctx_minimap_cursor.rect(zoomlevel * xoff_c, zoomlevel * yoff_c, zoomlevel, zoomlevel);
        ctx_minimap_cursor.stroke();
    }

    function getCenter() {
        var url = window.location.href;
        x_window = url.replace(re, '$2');
        y_window = url.replace(re, '$3');
        if (x_window == url || y_window == url) {
            x_window = 0;
            y_window = 0;
        }
        x_window = +x_window;
        y_window = +y_window;
        loadTemplates();
    }

    //-------------------------------------------------------------------------------------------

    function changeDisplay(id){
        let e = $(id);
        if (e.style.display == 'none') e.style.display = 'block';
        else e.style.display = 'none';
    };

    function $(id){return document.getElementById(id)};

    function log(msg){console.log(msg)};

    window.onkeydown = function(e) {
        switch(e.keyCode){
            case 50://2
                changeDisplay('settings');
                break;
            case 48://0
                if (localStorage.debug == 'true') {
                      localStorage.debug = false;
                    debug = false;
                    log('Debug is off')
                }else{
                localStorage.debug = true;
                debug = true;
                log('Debug is enabled')
                }
                break;
            case 51://3
                changeDisplay('settingsDiv');
                break;
        }
    };
})();
