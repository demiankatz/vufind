/* global VuFind */

VuFind.register('truncate', function Truncate() {
  function getSetting(settings, key, defaultVal = null) {
    // A lot of the code below would be easier if we could use nullish coalescing
    // (the ?? operator), but due to browser support concerns, this is safer:
    return (typeof settings[key] === 'undefined') ? defaultVal : settings[key];
  }

  function initTruncate(_container, _element, _fill) {
    var zeroHeightContainers = [];

    $(_container).not('.truncate-done').each(function truncate() {
      var container = $(this);
      var settings = container.data('truncate');

      var element = typeof _element !== 'undefined'
        ? container.find(_element)
        : (typeof settings.element !== 'undefined')
          ? container.find(settings.element)
          : false;
      var fill = typeof _fill === 'undefined' ? function fill(m) { return m; } : _fill;
      var rowCount = getSetting(settings, 'rows', 3);
      var moreLabel, lessLabel;
      moreLabel = lessLabel = getSetting(settings, 'label');
      if (moreLabel === null) {
        moreLabel = getSetting(settings, 'more-label', VuFind.translate('show_more'));
        lessLabel = getSetting(settings, 'less-label', VuFind.translate('show_less'));
      }
      var btnClass = getSetting(settings, 'btn-class') ? ' ' + settings['btn-class'] : '';
      var topToggle = getSetting(settings, 'top-toggle', Infinity);
      var inPlaceToggle = (element && getSetting(settings, 'in-place-toggle'))
        ? settings['in-place-toggle']
        : false;

      var parent, elementName, elementClass, numRows, shouldTruncate, truncatedHeight;

      if (element) {
        // Element-based truncation
        parent = element.parent();
        elementName = element.length && element.prop('tagName').toLowerCase();
        elementClass = element.length ? ' ' + element.prop('class') : '';
        numRows = container.find(element).length || 0;
        shouldTruncate = rowCount < numRows;

        if (shouldTruncate) {
          element.each(function hideRows(i) {
            if (i === rowCount) {
              $(this).addClass('truncate-start');
            }
            if (i >= rowCount) {
              $(this).hide();
              $(this).addClass('truncate-toggle');
            }
          });
        }
      } else {
        // Height-based truncation
        parent = container;
        elementName = 'div';
        elementClass = '';
        var rowHeight;
        if (container.children().length > 0) {
          // Use first child as the height element if available
          var heightElem = container.children().first();
          if (heightElem.is('div')) {
            rowHeight = parseFloat(heightElem.height());
          } else {
            rowHeight = parseFloat(heightElem.css('line-height').replace('px', ''));
          }
        } else {
          rowHeight = parseFloat(container.css('line-height').replace('px', ''));
        }
        numRows = Math.ceil(container.height() / rowHeight);
        shouldTruncate = rowCount < numRows;

        if (shouldTruncate) {
          truncatedHeight = rowCount * rowHeight;
          container.css('height', truncatedHeight + 'px');
        }
      }

      if (shouldTruncate) {
        var btnMore = '<button type="button" class="btn more-btn' + btnClass + '">' + moreLabel + ' <i class="fa fa-arrow-down" aria-hidden="true"></i></button>';
        var btnLess = '<button type="button" class="btn less-btn' + btnClass + '">' + lessLabel + ' <i class="fa fa-arrow-up" aria-hidden="true"></i></button>';
        var btnWrapper = $('<' + elementName + ' class="more-less-btn-wrapper' + elementClass + '"></' + elementName + '>');
        var btnWrapperBtm = btnWrapper.clone().append(fill(btnMore + btnLess));
        var btnWrapperTop = (numRows > topToggle) ? btnWrapper.clone().append(fill(btnLess)) : false;

        // Attach show/hide buttons to the top and bottom or display in place
        if (btnWrapperTop) {
          if (element) {
            btnWrapperTop.prependTo(parent);
          } else {
            btnWrapperTop.insertBefore(parent);
          }
        }
        if (inPlaceToggle) {
          btnWrapperBtm.insertBefore(parent.find('.truncate-start'));
        } else if (element) {
          btnWrapperBtm.appendTo(parent);
        } else {
          btnWrapperBtm.insertAfter(parent);
        }

        btnWrapperBtm.find('.less-btn').hide();
        if (btnWrapperTop) {
          btnWrapperTop.hide();
        }

        var onClickLessBtnHandler = function onClickLessBtn(/*event*/) {
          btnWrapperBtm.find('.less-btn').hide();
          if (btnWrapperTop) {
            btnWrapperTop.hide();
          }
          btnWrapperBtm.find('.more-btn').show();
          if (element) {
            container.find('.truncate-toggle').toggle();
          } else if (truncatedHeight === 0) {
            container.hide();
          } else {
            container.css('height', truncatedHeight + 'px');
          }
          btnWrapperBtm.find('.more-btn').focus();
        };
        btnWrapperBtm.find('.less-btn').click(onClickLessBtnHandler);
        if (btnWrapperTop) {
          btnWrapperTop.find('.less-btn').click(onClickLessBtnHandler);
        }

        btnWrapperBtm.find('.more-btn').click(function onClickMoreBtn(/*event*/) {
          $(this).hide();
          btnWrapperBtm.find('.less-btn').show();
          if (btnWrapperTop) {
            btnWrapperTop.show();
            btnWrapperTop.find('.less-btn').focus();
          } else {
            btnWrapperBtm.find('.less-btn').focus();
          }
          if (element) {
            container.find('.truncate-toggle').toggle();
          } else if (truncatedHeight === 0) {
            container.show();
          } else {
            container.css('height', 'auto');
          }
        });
      }

      container.addClass('truncate-done');

      if (truncatedHeight === 0) {
        zeroHeightContainers.push(container);
      }
    });

    // Hide zero-height containers. They are not hidden immediately to allow for
    // height calculation of nested containers.
    zeroHeightContainers.forEach(function hideContainer(container) {
      container.hide();
      container.css('height', 'auto');
    });
  }

  return {
    initTruncate: initTruncate
  };
});