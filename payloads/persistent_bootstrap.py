import sys

sys.path.insert(0, "/saves/yarpe")

TRIGGER = 'execfile("/saves/yarpe/persistent_bootstrap.py")'


class YarpeState(object):
    def __init__(self):
        self.logs = []
        self.game_initialized = False
        self.trigger_rearmed = False


renpy.store.yarpe_state = YarpeState()
ys = renpy.store.yarpe_state


def ylog(msg):
    ys.logs.append(msg)
    if len(ys.logs) > 400:
        del ys.logs[0:100]


ylog("YARPE: persistent bootstrap ran.")


class Yummy(object):
    def __reduce__(self):
        return renpy.python.py_exec, (TRIGGER,)

    def __deepcopy__(self, memo):
        new = Yummy()
        memo[id(self)] = new
        return new

    def __eq__(self, other):
        return isinstance(other, Yummy)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(TRIGGER)


def arm_trigger():
    p = renpy.game.persistent
    if not p:
        ylog("YARPE WARNING: renpy.game.persistent is not available, not re-armed")
        return False

    try:
        p.yarpe_trigger = Yummy()
        p._changed["yarpe_trigger"] = True
        ylog("YARPE: re-armed yarpe_trigger on the live persistent object.")
    except Exception as e:
        ylog("YARPE WARNING: persistent rejected the re-arm, %r" % e)
        return False
    return True


def yarpe_label_callback(label, abnormal):
    ylog("LABEL: %s (abnormal=%r)" % (label, abnormal))

    if not ys.trigger_rearmed:
        ys.trigger_rearmed = True
        arm_trigger()

    if label == "splashscreen" and not ys.game_initialized:
        ys.game_initialized = True
        ylog("YARPE: entered splashscreen, autoloading slot 1-1.")

        try:
            renpy.load("1-1")
        except Exception as e:
            ylog("YARPE ERROR: renpy.load(1-1) failed: %r" % e)


renpy.config.label_callback = yarpe_label_callback
ylog("YARPE: label_callback replaced with yarpe_label_callback.")
