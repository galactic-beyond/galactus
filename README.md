# GALACTUS

**This software is not yet production-ready and is pre-alpha (it has been made available to
placate the annoyingly yet adorably impatient among us). Questions and comments
will be ignored, and the askers/commenters will be shamed and humiliated until
the official stable release.**

## Overview

Galactus is the cortex of the Interlock Network. It coordinates blockchain-activities
(like setting staking yields and limits) and browser-activities (like communicating
with the ThreatSlayer extension to protect users, and to reward them for their browsing
activities). There is also some book-keeping involved, like memorizing user-configs.

Given its central role, it is designed to be robust from the very beginning. We have
organized the code as a state-machine, with explicit states and events, and assertions
that validate the consistency of the program at the beginning and end of every transition,
as well as on every read and write to any core, non-primitive object (i.e. galactus accounts).
The idea is to prevent mistakes ahead of time, instead of desperately trying to find and
fix the mistakes while the program actively causes damage (or -- in the best case -- refuses
to run).

We have also adopted the notion of stacks and concatenative programming for encoding
computations into transitions. We adopt the style of PushGP (where each major data-type
has its own stack) and Harel's statecharts (where computations happen in the interstice
betwee states -- the transtions). We implementent the concatenative/stack-based _notation_
using the very common fluent-programming style (i.e. `a.b().c().d().e()`).

A major advantage of combining fluent-programming with type-segragated stacks, is that
we get a **mostly** point-free style of programming (i.e. agglutinations of verbs but no
nouns -- only constructor-verbs take arguments, because those are a wholistic chunk of meaning --
which means that most code can be safely copy-pasted anywhere without having to rename anything),
and an **extremely** flexible and forgiving combinatory mode of expression 
(i.e. in `x.num(1).num(2).str('1').str('2').add().cat()`
we can swap the string and number operations with each other and get the same
result, because each stack represents its own computational continuity -- which
can provide obvious opportunities for parallelization, but that is more of an
aspiration).

Modeling the program as a set of unique states connected by unique transitions that
are triggered by unique events, gives coders the opportunity to program new features in an
append-only style (i.e. we rarely have to **change** code in existing transitions,
we just have to add new transitions and new states, while leaving everything else
as-is). Bug fixes are a different matter, and require modification, but such
modifiations are usually append-only affairs _internally_, if they require the addition/removal
of a new verb to the fleunt-call-chain. In fact, every single transition was implemented by
copying the original transition `begin-here -> ready`, renaming it, and replacing its
body, while keeping the boilerplate intact (there must be a way to reduce boilerplate with
decorators, but we have been too busy to look), and just passing the `(src, dst, event, trans_func)`
arguments to the `add_transition` method.

Fixing the internals of _verbs themselves_ will resemble the kinds of fixes that you are used
to doing in traditional code-bases, because the verb-internals are implemented using
variables. That said, most verbs lack complicated branching structures, because most
of branching is handled by the events and transitions in the state-machine. Some
transitions contain internal branches on events (i.e. getters for objects would create
dozens of unneccessary transitions, for no additional benefit). Some verbs are context
sensitive and branch extensively on context (i.e. the `data_load` and `data_store` verbs
need to branch on a context-object to know which stack to push the data to, and also how
to deserialize the returned data-rows).

The verbs are analogous to the system-calls given by an operating system to its application
-- they connect the endogenous logic of the program to the exogenous reality of the world.
They present a clean separation between the _spirit_ of the program and the _manifestation_
of that spirit in the external world. The verbs modify the stacks, and they emit events
(which the statemachine then reacts to). To modify the stacks, the verbs need to use the
push/pop/peek methods, which check for access-priviledges (each verb must specify ahead of time
which stacks it intends to read and write from -- this catches a surprising number of bugs
early on). Just like a system-call, a call into a verb passes control from the state-machine 
(encoded in the `Endo` class) to the `Exo` class which is where the verbs are
implemented -- these 2 classes communicate via the stacks, passing control back and forth
between each other.

Unlike Harel's statecharts, which distinguish between events (missable external
signals from the outside world) and _conditions_ (boolean values derived from
data internal to the program-memory), we overload the events and handle the
distinction in the verb itself -- this allows us to easily create stochastified
mocks, inside the verbs, to exercise all transitions without having to stress
over the semantic distinction between an event and a condition.

We use the `hypothesis` framework to generate test data and to drive event/data-inputs
into the state-machine. If any assertion gets triggered, hypothesis tries to create
the smallest possible input-sequence that would trigger the assertion.

## Cool Features
### Tests / Fuzzing
### Heatmaps
### Stochastification

# Credits/Acknowledgements/Related-Work

TODO References to wiki-pages and sources go here
